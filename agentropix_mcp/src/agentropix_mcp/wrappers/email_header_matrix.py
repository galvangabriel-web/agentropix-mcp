"""W-172 — email-header matrix MCP wrapper (closes GH #17 MailAgent gap).

The 2026-05-05 mail deep-dive (``MAIL-DEEP-DIVE-20260505T224352Z``)
surfaced typosquat ``stark-research-labs.co`` From: addresses through
direct CC-BASH bash + ``eml_parser`` + ``extract_msg`` calls because
the MCP surface lacked a primitive for "header matrix from a corpus
of .eml/.msg messages". MailAgent (GH #17) is the consumer that has
emitted 0 findings ever since: the missing primitive is the gating
dependency.

This wrapper builds that primitive. Walks ``corpus_dir`` for ``.eml``
and ``.msg`` messages, parses each into a typed per-message row
(Date / From / Reply-To / Return-Path / Message-ID / Subject /
Authentication-Results SPF/DKIM/DMARC / first Received: hop), and
returns a summary aggregate.

Engine matrix:
    .eml  → stdlib :mod:`email.parser` (always available) for the
            header parse; ``Authentication-Results`` is regex-scanned
            for ``spf=`` / ``dkim=`` / ``dmarc=`` verdicts.
    .msg  → optional ``extract_msg`` (pip extra ``mail``). Wrapper
            degrades cleanly when absent — .msg files surface as
            ``ok=False`` rows with an explanatory ``error`` plus a
            single warning row in the result so the consumer LLM
            sees the missing-dep state without grepping logs.
    auto  → suffix dispatch (default).

Path safety:
    * Thymus path validation is enforced at the wrapper entry per
      W-172 spec (``Wrapper must call thymus path validation on
      corpus_dir``). Extra defensive ``..``-segment screen runs
      before Thymus so the rejection reason is precise.
    * Per-message header parsing is bounded by
      ``AGENTROPIX_EMAIL_MAX_BYTES`` (default 32 MiB, floor 4 KiB,
      ceiling 1 GiB) so a crafted huge-body message cannot wedge the
      parser. Files larger than the cap surface as ``ok=False`` rows
      with the size + cap in the ``error`` field.
    * Walk is bounded by ``AGENTROPIX_EMAIL_MAX_MESSAGES`` (default
      100,000) — past the cap, the result carries ``truncated=True``
      in the summary.

Returns a plain ``dict`` whose shape is the JSON contract documented
in the W-172 ticket. The wrapper deliberately returns ``dict`` rather
than a Pydantic model so the FastMCP layer can pass it through
``model_dump``-style without an extra adapter; consumers that want
typed access can wrap the result in their own ``BaseModel``.
"""

from __future__ import annotations

import email
import email.parser
import email.policy
import email.utils
import logging
import os
import re
from collections.abc import Iterable
from datetime import datetime, timezone
from email.message import Message
from pathlib import Path
from typing import Any

from agentropix_mcp._env import get_int
from agentropix_mcp.thymus_policy import ThymusEvidencePolicy

logger = logging.getLogger(__name__)

# ----- Defaults ----------------------------------------------------------- #

# Per-message size cap. 32 MiB is well above any sane email; bounded so a
# pathological 4 GiB attachment can't wedge the stdlib parser's bytes-into-
# str path. Floor 4 KiB to prevent a typo'd `=0` env from interpreting as
# "skip everything"; ceiling 1 GiB so we don't overflow downstream byte math.
_DEFAULT_MAX_BYTES = 32 * 1024 * 1024
_FLOOR_MAX_BYTES = 4 * 1024
_CEILING_MAX_BYTES = 1 * 1024 * 1024 * 1024

# Walk cap. 100k matches the order of magnitude of a forensic mail-server
# carve (the 2026-05-05 MAIL-DEEP-DIVE produced 200 candidates from one
# 17 GiB image; an enterprise-scale carve could plausibly produce 50k+).
_DEFAULT_MAX_MESSAGES = 100_000
_FLOOR_MAX_MESSAGES = 1
_CEILING_MAX_MESSAGES = 10_000_000

# ----- Optional dependency probe ----------------------------------------- #

try:  # pragma: no cover — dependency-probe path
    import eml_parser as _eml_parser  # type: ignore[import-not-found]

    _HAS_EML_PARSER = True
except ImportError:  # pragma: no cover
    _eml_parser = None  # type: ignore[assignment]
    _HAS_EML_PARSER = False

try:  # pragma: no cover
    import extract_msg as _extract_msg  # type: ignore[import-not-found]

    _HAS_EXTRACT_MSG = True
except ImportError:  # pragma: no cover
    _extract_msg = None  # type: ignore[assignment]
    _HAS_EXTRACT_MSG = False

# ----- Regex patterns ---------------------------------------------------- #

# Authentication-Results: spf=pass | dkim=fail | dmarc=none — RFC 8601 lists
# the value alphabet, but in the wild we see permissive whitespace and
# semi-canonical capitalization. Match case-insensitively, return lower.
_AUTH_RESULT_RE = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z]+)",
    re.IGNORECASE,
)

# RFC 5322 angle-addr extraction. The display-name portion is whatever
# precedes the angle bracket, after stripping outer quotes. Bare-address
# fallback handles malformed `From: alice@example.com` (no angles).
_ANGLE_ADDR_RE = re.compile(r"<([^>]+@[^>]+)>")
_BARE_ADDR_RE = re.compile(r"([\w.+-]+@[\w.-]+\.[a-zA-Z]{2,})")

_VALID_FORMATS = frozenset({"eml", "msg", "auto"})

# ----- Thymus singleton --------------------------------------------------- #

# Constructed lazily on first use so the import doesn't pay the cost when
# the wrapper isn't called (most pytest runs that don't touch this file).
_thymus: ThymusEvidencePolicy | None = None


def _get_thymus() -> ThymusEvidencePolicy:
    global _thymus
    if _thymus is None:
        _thymus = ThymusEvidencePolicy()
    return _thymus


# ----- Helpers ----------------------------------------------------------- #


def _validate_corpus_dir(corpus_dir: str) -> Path:
    """Validate ``corpus_dir`` for traversal + Thymus before any walk.

    Order is deliberate:
      1. Type / non-empty check — surfaces ``ValueError`` rather than a
         confusing ``Path('').exists()`` False.
      2. ``..`` segment screen — gives a precise traversal-segment
         error before normpath inside Thymus collapses the segment.
      3. Thymus ``check_read`` — defense-in-depth; the MCP surface
         layer is the authoritative gate, but we re-check here per
         W-172 spec ("Wrapper must call thymus path validation on
         corpus_dir").
      4. Filesystem existence + is-directory check.
    """
    if not isinstance(corpus_dir, str) or not corpus_dir:
        raise ValueError("corpus_dir must be a non-empty string")
    if ".." in corpus_dir.split("/"):
        raise ValueError(
            f"corpus_dir contains traversal segment '..': {corpus_dir!r}"
        )
    violation = _get_thymus().check_read(corpus_dir)
    if violation:
        raise ValueError(f"thymus rejected corpus_dir: {violation}")
    p = Path(corpus_dir)
    if not p.exists():
        raise FileNotFoundError(f"corpus_dir not found: {corpus_dir}")
    if not p.is_dir():
        raise ValueError(f"corpus_dir is not a directory: {corpus_dir}")
    return p


def _extract_addr(raw: str) -> tuple[str, str]:
    """Return ``(display_name, email_address)`` from a raw From: value.

    Tolerates the four shapes seen in the 2026-05-05 corpus:
        ``Alice <alice@example.com>``           — angle-addr + DN
        ``"Alice Sender" <alice@example.com>``  — quoted DN
        ``alice@example.com``                   — bare addr
        ``alice <alice@example.com>``           — bare DN, no quotes
    """
    if not raw:
        return "", ""
    raw = raw.strip()
    m = _ANGLE_ADDR_RE.search(raw)
    if m:
        addr = m.group(1).strip()
        dn = raw[: m.start()].strip()
        if dn.startswith('"') and dn.endswith('"') and len(dn) >= 2:
            dn = dn[1:-1].strip()
        return dn, addr
    m = _BARE_ADDR_RE.search(raw)
    if m:
        return "", m.group(1).strip()
    return "", ""


def _parse_auth_results(value: str | None) -> tuple[str, str, str]:
    """Extract ``(spf, dkim, dmarc)`` verdicts from one or many AR headers.

    ``value`` is the raw concatenation of every Authentication-Results
    header (RFC 8601 allows multiple). First non-``none`` verdict for
    each method wins, matching the receive-side "first hop trusted"
    convention. Missing methods default to ``"none"``.
    """
    if not value:
        return "none", "none", "none"
    found: dict[str, str] = {"spf": "none", "dkim": "none", "dmarc": "none"}
    for m in _AUTH_RESULT_RE.finditer(value):
        method = m.group(1).lower()
        verdict = m.group(2).lower()
        if method in found and found[method] == "none":
            found[method] = verdict
    return found["spf"], found["dkim"], found["dmarc"]


def _first_received_hop(received_headers: list[str]) -> str:
    """Return the originating-relay Received: line, single-line normalised.

    Email-style Received: stamps are prepended in reverse chronological
    order — the *last* entry in ``Message.get_all('Received')`` is the
    hop closest to the sender (the "first received hop" in human
    terms). Multi-line values are flattened to a single line so the
    result fits on one row of an LLM-rendered table.
    """
    if not received_headers:
        return ""
    raw = received_headers[-1]
    # Collapse continuation whitespace + line breaks.
    return re.sub(r"\s+", " ", raw).strip()


def _normalise_date(raw: str) -> tuple[str, str]:
    """Parse an RFC 2822 ``Date:`` value into ``(iso_8601, raw)``.

    Returns ``("", raw)`` when the input is unparseable so the row
    keeps ``date == ""`` (not the malformed string) — that way the
    summary's lexical min/max can't pick up partial-header fragments
    like ``"Fri,"`` from a carved corpus.
    """
    if not raw:
        return "", ""
    try:
        dt = email.utils.parsedate_to_datetime(raw)
    except (TypeError, ValueError, IndexError):
        return "", raw
    if dt is None:
        return "", raw
    if dt.tzinfo is None:
        # RFC 2822 says missing TZ → treat as UTC; matches what
        # eml_parser does and keeps comparisons monotonic.
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(), raw


def _empty_row(path: str, error: str) -> dict[str, Any]:
    return {
        "path": path,
        "date": "",
        "date_raw": "",
        "from_header": "",
        "from_email": "",
        "from_display_name": "",
        "reply_to": "",
        "return_path": "",
        "message_id": "",
        "subject": "",
        "spf": "none",
        "dkim": "none",
        "dmarc": "none",
        "first_received_hop": "",
        "ok": False,
        "error": error,
    }


def _row_from_message(path: str, msg: Message) -> dict[str, Any]:
    """Build one header-matrix row from a parsed stdlib email.Message."""
    from_header = msg.get("From", "") or ""
    display_name, from_email = _extract_addr(from_header)

    # Authentication-Results may appear multiple times in the wild —
    # concatenate so the regex sees every line once.
    auth_results_all = msg.get_all("Authentication-Results") or []
    spf, dkim, dmarc = _parse_auth_results("\n".join(auth_results_all))

    received_all = msg.get_all("Received") or []
    first_hop = _first_received_hop(received_all)

    message_id = msg.get("Message-ID", "") or ""
    subject = msg.get("Subject", "") or ""

    has_signal = bool(message_id or from_email or subject)

    raw_date = (msg.get("Date", "") or "").strip()
    iso_date, raw_date = _normalise_date(raw_date)

    return {
        "path": path,
        "date": iso_date,
        "date_raw": raw_date,
        "from_header": from_header,
        "from_email": from_email,
        "from_display_name": display_name,
        "reply_to": (msg.get("Reply-To", "") or "").strip(),
        "return_path": (msg.get("Return-Path", "") or "").strip(),
        "message_id": message_id.strip(),
        "subject": subject.strip(),
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "first_received_hop": first_hop,
        "ok": has_signal,
        "error": "" if has_signal else "no recognizable headers",
    }


def _parse_one_eml(path: Path, max_bytes: int) -> dict[str, Any]:
    """Parse one ``.eml`` file. Bytes-bounded, exception-safe."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        return _empty_row(str(path), f"stat failed: {exc}")
    if size > max_bytes:
        return _empty_row(
            str(path),
            f"file size {size} exceeds AGENTROPIX_EMAIL_MAX_BYTES={max_bytes}",
        )
    try:
        with path.open("rb") as fh:
            raw = fh.read(max_bytes)
    except OSError as exc:
        return _empty_row(str(path), f"read failed: {exc}")
    if not raw.strip():
        return _empty_row(str(path), "file is empty")
    try:
        # compat32 — most permissive policy. RFC 6532 internationalised
        # headers parse fine; malformed input degrades to empty fields
        # rather than raising, which is what we want for forensic carve
        # corpora full of partial messages.
        msg = email.parser.BytesParser(policy=email.policy.compat32).parsebytes(raw)
    except Exception as exc:  # noqa: BLE001 — defensive carve-corpus parsing
        return _empty_row(str(path), f"parse failed: {exc}")
    return _row_from_message(str(path), msg)


def _parse_one_msg(path: Path, max_bytes: int) -> dict[str, Any]:
    """Parse one ``.msg`` file via ``extract_msg`` (optional dep)."""
    if not _HAS_EXTRACT_MSG:
        return _empty_row(
            str(path),
            "extract_msg unavailable - install with `uv sync --extra mail`",
        )
    try:
        size = path.stat().st_size
    except OSError as exc:
        return _empty_row(str(path), f"stat failed: {exc}")
    if size > max_bytes:
        return _empty_row(
            str(path),
            f"file size {size} exceeds AGENTROPIX_EMAIL_MAX_BYTES={max_bytes}",
        )
    try:
        m = _extract_msg.Message(str(path))  # type: ignore[union-attr]
    except Exception as exc:  # noqa: BLE001
        return _empty_row(str(path), f"extract_msg parse failed: {exc}")
    try:
        from_header = (getattr(m, "sender", "") or "").strip()
        display_name, from_email = _extract_addr(from_header)
        subject = (getattr(m, "subject", "") or "").strip()
        message_id = (getattr(m, "messageId", "") or "").strip()
        date_value = getattr(m, "date", "")
        # extract_msg's .date is a datetime in newer versions. Normalise
        # to UTC ISO-8601 for parity with the .eml path; preserve the
        # raw string in date_raw for forensic provenance.
        if hasattr(date_value, "isoformat"):
            dt_aware = date_value if date_value.tzinfo else date_value.replace(tzinfo=timezone.utc)
            iso_date = dt_aware.astimezone(timezone.utc).isoformat()
            date_raw_str = str(date_value)
        elif date_value:
            iso_date, date_raw_str = _normalise_date(str(date_value))
        else:
            iso_date, date_raw_str = "", ""
        has_signal = bool(message_id or from_email or subject)
        # The .msg format embeds Internet headers as a single string when
        # present; pump it through the stdlib parser for SPF/DKIM/DMARC.
        ih = getattr(m, "header", None) or getattr(m, "transportMessageHeaders", None) or ""
        spf = dkim = dmarc = "none"
        first_hop = ""
        if isinstance(ih, str) and ih.strip():
            try:
                hdr_msg = email.parser.Parser(policy=email.policy.compat32).parsestr(ih)
                ar_all = hdr_msg.get_all("Authentication-Results") or []
                spf, dkim, dmarc = _parse_auth_results("\n".join(ar_all))
                first_hop = _first_received_hop(hdr_msg.get_all("Received") or [])
            except Exception as exc:  # noqa: BLE001
                logger.debug("extract_msg header re-parse failed for %s: %s", path, exc)
        return {
            "path": str(path),
            "date": iso_date,
            "date_raw": date_raw_str,
            "from_header": from_header,
            "from_email": from_email,
            "from_display_name": display_name,
            "reply_to": (getattr(m, "replyTo", "") or "").strip(),
            "return_path": "",
            "message_id": message_id,
            "subject": subject,
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
            "first_received_hop": first_hop,
            "ok": has_signal,
            "error": "" if has_signal else "no recognizable headers",
        }
    finally:
        try:
            m.close()
        except Exception:  # noqa: BLE001
            pass


def _walk_corpus(corpus_path: Path, want_format: str) -> Iterable[Path]:
    """Yield candidate files under ``corpus_path`` for the chosen format.

    Symlink-aware walk: ``os.walk(..., followlinks=False)`` does NOT
    descend into directory symlinks (defeats a malicious symlink
    pointing at ``/etc/`` that would otherwise expose unallowed paths
    to the parser). After yielding each candidate we re-resolve and
    confirm the file's resolved path stays inside ``corpus_path`` —
    catches a single-file symlink that points outside without
    crossing a directory boundary. Sort by path so the result-set is
    deterministic (helps chain-of-custody hashing).
    """
    suffixes: tuple[str, ...]
    if want_format == "eml":
        suffixes = (".eml",)
    elif want_format == "msg":
        suffixes = (".msg",)
    else:  # auto
        suffixes = (".eml", ".msg")
    corpus_resolved = corpus_path.resolve()
    candidates: list[Path] = []
    for dirpath, _dirnames, filenames in os.walk(corpus_path, followlinks=False):
        for name in filenames:
            p = Path(dirpath) / name
            if p.suffix.lower() not in suffixes:
                continue
            try:
                resolved = p.resolve()
                resolved.relative_to(corpus_resolved)
            except (ValueError, OSError):
                logger.warning(
                    "skipping %s — resolves outside corpus_dir (symlink escape)", p
                )
                continue
            candidates.append(p)
    yield from sorted(candidates)


def _summarise(rows: list[dict[str, Any]], truncated: bool) -> dict[str, Any]:
    ok_rows = [r for r in rows if r.get("ok")]
    unique_from = {r.get("from_email", "") for r in ok_rows if r.get("from_email")}
    spf_fail = sum(1 for r in ok_rows if r.get("spf") == "fail")
    dkim_fail = sum(1 for r in ok_rows if r.get("dkim") == "fail")
    dmarc_fail = sum(1 for r in ok_rows if r.get("dmarc") == "fail")
    dates = [r.get("date", "") for r in ok_rows if r.get("date")]
    return {
        "n_messages": len(ok_rows),
        "n_unique_from_emails": len(unique_from),
        "spf_fail_count": spf_fail,
        "dkim_fail_count": dkim_fail,
        "dmarc_fail_count": dmarc_fail,
        "earliest_date": min(dates) if dates else "",
        "latest_date": max(dates) if dates else "",
        "truncated": truncated,
        "n_files_scanned": len(rows),
    }


def _build_warnings(saw_eml: bool, saw_msg: bool) -> list[str]:
    """Surface optional-dep gaps so the consumer LLM doesn't silently miss them."""
    warnings: list[str] = []
    if saw_eml and not _HAS_EML_PARSER:
        warnings.append(
            "eml_parser not installed - SPF/DKIM/DMARC parsed via stdlib regex; "
            "install via `uv sync --extra mail` for the deeper structured parser."
        )
    if saw_msg and not _HAS_EXTRACT_MSG:
        warnings.append(
            "extract_msg not installed - .msg files cannot be parsed; "
            "install via `uv sync --extra mail`."
        )
    return warnings


# ----- Public entry point ------------------------------------------------ #


def mcp_email_header_matrix(corpus_dir: str, format: str = "auto") -> dict[str, Any]:
    """Build a per-message header matrix for a corpus of ``.eml`` / ``.msg`` files.

    Args:
        corpus_dir: Directory containing email message files.
            Validated against Thymus before any walk.
        format: ``"eml"``, ``"msg"``, or ``"auto"`` (default — both).

    Returns:
        A dict with two keys:
          * ``messages`` — list of per-file rows. Each row contains
            ``path``, ``date``, ``from_header``, ``from_email``,
            ``from_display_name``, ``reply_to``, ``return_path``,
            ``message_id``, ``subject``, ``spf``, ``dkim``, ``dmarc``,
            ``first_received_hop``, ``ok``, ``error``.
          * ``summary`` — aggregate counts: ``n_messages``,
            ``n_unique_from_emails``, ``spf_fail_count``,
            ``dkim_fail_count``, ``dmarc_fail_count``,
            ``earliest_date``, ``latest_date``, ``truncated``,
            ``n_files_scanned``.
          * ``warnings`` — optional-dep state messages (empty list
            when both ``eml_parser`` and ``extract_msg`` are present).

    Raises:
        ValueError: ``format`` not in ``{eml, msg, auto}``;
            ``corpus_dir`` contains a traversal segment, fails Thymus,
            or is not a directory.
        FileNotFoundError: ``corpus_dir`` does not exist.
    """
    if format not in _VALID_FORMATS:
        raise ValueError(
            f"format must be one of {sorted(_VALID_FORMATS)}, got {format!r}"
        )

    corpus_path = _validate_corpus_dir(corpus_dir)

    max_bytes = get_int(
        "AGENTROPIX_EMAIL_MAX_BYTES",
        _DEFAULT_MAX_BYTES,
        floor=_FLOOR_MAX_BYTES,
        ceiling=_CEILING_MAX_BYTES,
    )
    max_messages = get_int(
        "AGENTROPIX_EMAIL_MAX_MESSAGES",
        _DEFAULT_MAX_MESSAGES,
        floor=_FLOOR_MAX_MESSAGES,
        ceiling=_CEILING_MAX_MESSAGES,
    )

    rows: list[dict[str, Any]] = []
    truncated = False
    saw_eml = False
    saw_msg = False

    for path in _walk_corpus(corpus_path, format):
        if len(rows) >= max_messages:
            truncated = True
            logger.warning(
                "email_header_matrix walk truncated at %d messages "
                "(AGENTROPIX_EMAIL_MAX_MESSAGES); remaining files skipped",
                max_messages,
            )
            break
        suffix = path.suffix.lower()
        if suffix == ".eml":
            saw_eml = True
            rows.append(_parse_one_eml(path, max_bytes))
        elif suffix == ".msg":
            saw_msg = True
            rows.append(_parse_one_msg(path, max_bytes))

    summary = _summarise(rows, truncated)
    warnings = _build_warnings(saw_eml, saw_msg)

    return {
        "tool": "email_header_matrix",
        "corpus_dir": str(corpus_path),
        "format": format,
        "messages": rows,
        "summary": summary,
        "warnings": warnings,
    }


__all__ = ["mcp_email_header_matrix"]
