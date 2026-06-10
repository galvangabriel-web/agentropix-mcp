"""W-210 — PST carve + attachment-hash IOC index MCP wrapper.

The capstone of the W-229 derivation chain (W-216 + W-217 + W-218 +
W-229 + W-230 + W-231). Given a single PST/OST file on disk, runs the
``parse_pst_with_recovery`` orchestrator (pypff + opt-in pffexport
fallback) and returns a structured forensic report:

* ``messages`` — per-message rows: subject / sender / date /
  attachment count / engine that produced the row
  (``"pypff"`` vs ``"pffexport_recovered"`` vs
  ``"pffexport_recovery_failed"``).
* ``iocs`` — flat per-attachment rows: SHA-256, filename, byte size,
  back-reference to the message that contained it (subject + sender +
  date + engine + source PST path). Each row is a complete chain-of-
  custody record.
* ``ioc_index`` — ``{sha256: [ioc_row, ...]}`` for O(1) hash-pivot
  queries. The same hash can appear under multiple messages (forwarded
  emails, FW: threads), so the value is a list.
* ``summary`` — aggregate counts the consumer LLM needs to write an
  audit paragraph: clean / recovered / failed message counts,
  attachment totals, unique-hash count.

Path safety:
    * Thymus path validation (W-172 pattern) — defense-in-depth gate
      before any I/O.
    * Per-PST size cap ``AGENTROPIX_PST_CARVE_MAX_BYTES`` (default
      1 GiB, floor 4 KiB, ceiling 32 GiB). PSTs larger than the cap
      surface a ``warnings`` entry and an empty ``iocs`` list.

Engine choice is delegated to ``parse_pst_with_recovery``. Operators
who need to disable the pffexport fallback set
``AGENTROPIX_MAIL_RECOVERY_ENABLED=0`` (SIFT-W-230 kill switch). The
configurable tempdir (``AGENTROPIX_PFF_RECOVERY_TMPDIR``, SIFT-W-231)
keeps attachment bytes on the case-folder volume.

Returns a plain ``dict`` so the FastMCP layer can ``model_dump``-style
serialize it without an extra adapter; consumers that want typed
access can wrap the result in their own ``BaseModel``.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path
from typing import Any

from agentropix_mcp._env import get_int
from agentropix_mcp.thymus_policy import ThymusEvidencePolicy
from agentropix_mcp.wrappers._mail_parsers import parse_pst_with_recovery

logger = logging.getLogger(__name__)

# Per-PST size cap. 1 GiB matches the order of magnitude of an
# enterprise PST (Outlook's default OST cap on Office 365 is 50 GiB
# but a single PST file on a forensic image is typically 100 MiB-2 GiB
# — see the SRL-2015 nromanoff PST at 57 MiB). Floor 4 KiB prevents a
# misconfigured `=0` env from suppressing every input; ceiling 32 GiB
# matches Outlook's modern hard limit.
_PST_CARVE_MAX_BYTES_ENV = "AGENTROPIX_PST_CARVE_MAX_BYTES"
_PST_CARVE_MAX_BYTES_DEFAULT = 1 * 1024 * 1024 * 1024
_PST_CARVE_MAX_BYTES_FLOOR = 4 * 1024
_PST_CARVE_MAX_BYTES_CEILING = 32 * 1024 * 1024 * 1024

# Lazy Thymus singleton — same pattern as W-172.
_thymus: ThymusEvidencePolicy | None = None


def _get_thymus() -> ThymusEvidencePolicy:
    global _thymus
    if _thymus is None:
        _thymus = ThymusEvidencePolicy()
    return _thymus


_PST_MAGIC = b"!BDN"  # libpff "Personal Folder File" signature (PST + OST share it)


def _validate_pst_path(path: str) -> Path:
    """Validate ``path`` for traversal + Thymus + file existence + magic.

    Order mirrors the W-172 email_header_matrix gate, with two extra
    forensic-grade gates added per the W-210 5-critic review:
      1. Type / non-empty.
      2. ``..`` segment screen — precise error before normpath collapse.
      3. Thymus ``check_read``.
      4. Filesystem checks (exists + is_file).
      5. Symlink rejection (defense-in-depth — Thymus also rejects
         escapes, but a `.pst` symlink to ``/etc/passwd`` should fail
         at this layer too).
      6. Suffix check — PST/OST only.
      7. Magic-byte sniff (``!BDN``) — rejects files named ``*.pst``
         that aren't actually PST containers before any large read.
    """
    if not isinstance(path, str) or not path:
        raise ValueError("path must be a non-empty string")
    if ".." in path.split("/"):
        raise ValueError(f"path contains traversal segment '..': {path!r}")
    violation = _get_thymus().check_read(path)
    if violation:
        raise ValueError(f"thymus rejected path: {violation}")
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"PST not found: {path}")
    if p.is_symlink():
        raise ValueError(f"path is a symlink (forensic policy forbids): {path}")
    if not p.is_file():
        raise ValueError(f"path is not a regular file: {path}")
    if p.suffix.lower() not in (".pst", ".ost"):
        raise ValueError(f"unsupported suffix {p.suffix!r}; expected .pst or .ost")
    with p.open("rb") as fh:
        magic = fh.read(len(_PST_MAGIC))
    if magic != _PST_MAGIC:
        raise ValueError(f"file does not start with PST magic {_PST_MAGIC!r}: got {magic!r}")
    return p


def _engine_label(parser_note: str) -> str:
    """Map a ``MailMessage.parser_note`` to a stable engine label."""
    if not parser_note:
        return "pypff"
    if parser_note.startswith("pffexport_recovered"):
        return "pffexport_recovered"
    if parser_note.startswith("pffexport_recovery_failed"):
        return "pffexport_recovery_failed"
    return "deferral"  # e.g. empty_message_store, pypff_failed


def carve_pst_iocs(path: str) -> dict[str, Any]:
    """Carve a PST/OST file into a per-message + per-attachment IOC report.

    Args:
        path: Filesystem path to a ``.pst`` or ``.ost`` file. Validated
            against Thymus + traversal before any I/O.

    Returns:
        A dict with keys:
          * ``tool`` — ``"carve_pst_iocs"``.
          * ``source_pst`` — the validated input path (string form).
          * ``messages`` — per-message rows: ``subject``, ``sender``,
            ``date``, ``recipients``, ``n_attachments``, ``engine``,
            ``parser_note``.
          * ``iocs`` — per-attachment rows: ``sha256``, ``filename``,
            ``size``, ``mime_type`` (always None on the pypff path),
            ``source_subject``, ``source_sender``, ``source_date``,
            ``source_engine``, ``source_parser_note`` (full W-231
            chain-of-custody marker), ``source_pst``.
          * ``ioc_index`` — ``{sha256: [ioc_row, ...]}`` for hash pivots.
          * ``summary`` — ``n_messages_total``, ``n_messages_pypff``,
            ``n_messages_recovered``, ``n_messages_recovery_failed``,
            ``n_messages_deferral``, ``n_attachments_total``,
            ``n_unique_hashes``, ``pst_size_bytes``, ``truncated``.
          * ``warnings`` — soft-error messages (oversize PST, etc.).

    Raises:
        ValueError: ``path`` traversal, Thymus rejection, wrong suffix,
            or non-file path.
        FileNotFoundError: ``path`` does not exist.
    """
    pst_path = _validate_pst_path(path)

    max_bytes = get_int(
        _PST_CARVE_MAX_BYTES_ENV,
        _PST_CARVE_MAX_BYTES_DEFAULT,
        floor=_PST_CARVE_MAX_BYTES_FLOOR,
        ceiling=_PST_CARVE_MAX_BYTES_CEILING,
    )
    pst_size = pst_path.stat().st_size
    warnings: list[str] = []
    truncated = False

    if pst_size > max_bytes:
        warnings.append(
            f"PST size {pst_size} bytes exceeds "
            f"{_PST_CARVE_MAX_BYTES_ENV} cap of {max_bytes} bytes — "
            f"skipping carve"
        )
        return {
            "tool": "carve_pst_iocs",
            "source_pst": str(pst_path),
            "messages": [],
            "iocs": [],
            "ioc_index": {},
            "summary": {
                "n_messages_total": 0,
                "n_messages_pypff": 0,
                "n_messages_recovered": 0,
                "n_messages_recovery_failed": 0,
                "n_messages_deferral": 0,
                "n_attachments_total": 0,
                "n_unique_hashes": 0,
                "pst_size_bytes": pst_size,
                "truncated": True,
            },
            "warnings": warnings,
        }

    content = pst_path.read_bytes()
    messages = parse_pst_with_recovery(content, pst_path)

    message_rows: list[dict[str, Any]] = []
    ioc_rows: list[dict[str, Any]] = []
    ioc_index: dict[str, list[dict[str, Any]]] = defaultdict(list)
    counts = {
        "pypff": 0,
        "pffexport_recovered": 0,
        "pffexport_recovery_failed": 0,
        "deferral": 0,
    }

    for m in messages:
        engine = _engine_label(m.parser_note)
        counts[engine] += 1
        message_rows.append(
            {
                "subject": m.subject,
                "sender": m.sender,
                "date": m.date,
                "recipients": list(m.recipients),
                "n_attachments": len(m.attachments),
                "engine": engine,
                "parser_note": m.parser_note,
            }
        )
        for att in m.attachments:
            ioc = {
                "sha256": att.content_hash,
                "filename": att.filename,
                "size": att.size,
                # Always None on the pypff path (libpff does not expose
                # the MAPI PR_ATTACH_MIME_TAG property). Surfaced for
                # eventual `extract_msg` / `eml_parser` paths that do.
                "mime_type": att.mime_type,
                "source_subject": m.subject,
                "source_sender": m.sender,
                "source_date": m.date,
                "source_engine": engine,
                # Carries the W-231 chain-of-custody marker (e.g.
                # "pffexport_recovered:synthesized_eml:v20180714") so
                # each IOC row is self-contained for downstream audit.
                "source_parser_note": m.parser_note,
                "source_pst": str(pst_path),
            }
            ioc_rows.append(ioc)
            if att.content_hash:
                ioc_index[att.content_hash].append(ioc)

    summary = {
        "n_messages_total": len(message_rows),
        "n_messages_pypff": counts["pypff"],
        "n_messages_recovered": counts["pffexport_recovered"],
        "n_messages_recovery_failed": counts["pffexport_recovery_failed"],
        "n_messages_deferral": counts["deferral"],
        "n_attachments_total": len(ioc_rows),
        "n_unique_hashes": len(ioc_index),
        "pst_size_bytes": pst_size,
        "truncated": truncated,
    }

    return {
        "tool": "carve_pst_iocs",
        "source_pst": str(pst_path),
        "messages": message_rows,
        "iocs": ioc_rows,
        "ioc_index": dict(ioc_index),
        "summary": summary,
        "warnings": warnings,
    }


__all__ = ["carve_pst_iocs"]
