"""MailAgent (issue #17) — detect MITRE T1566 (Phishing) sub-techniques
from PST / OST / MSG / EML mail artifacts.

On disk hosts the agent consults
``mcp_list_files`` for any of the documented mail extensions under
``image.parent`` and dispatches each file to the appropriate parser; in
tests the ``_run_on_text`` helper takes raw bytes / text directly so the
parser-and-detector pipeline can be exercised without a filesystem.

Detectors fired:

* :func:`detect_dangerous_attachments` -- ``T1566.001`` (executable atts)
* :func:`detect_macro_documents`       -- ``T1566.001`` (macro Office)
* :func:`detect_link_mismatch`         -- ``T1566.002`` (anchor mismatch)
* :func:`detect_oauth_phish`           -- ``T1566.003`` (OAuth consent)
* :func:`detect_lookalike_sender`      -- ``T1566`` (lookalike domains)
* :func:`detect_auth_failure`          -- ``T1566`` (SPF/DKIM/DMARC fail)

Tunables (env-var, all clamped):

* ``AGENTROPIX_MAIL_MAX_BYTES``           (int, default 50_000_000,
  [4_096, 500_000_000])
* ``AGENTROPIX_MAIL_MAX_MESSAGES``        (int, default 5_000, [1, 100_000])
* ``AGENTROPIX_MAIL_LOOKALIKE_DISTANCE``  (int, default 2, [1, 5])

**W-219 update (2026-05-17):** PST/OST and MSG containers are now fully
parsed via ``pypff`` and ``extract_msg`` respectively. The agent emits
real T1566 findings end-to-end from carved Outlook artefacts. On
``pypff`` / ``extract_msg`` failure the parsers fall back to a single
deferral row whose ``parser_note`` carries the failure cause and
(for PST) the verbatim ``pffexport`` recovery recipe.
"""

from __future__ import annotations

import hashlib
import logging
import re
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path

from agentropix_mcp.agents._base import Finding, SwarmAgent
from agentropix_mcp.agents._evidence import looks_like_memory
from agentropix_mcp.agents._mail_detectors import (
    detect_auth_failure,
    detect_dangerous_attachments,
    detect_link_mismatch,
    detect_lookalike_sender,
    detect_macro_documents,
    detect_oauth_phish,
)
from agentropix_mcp.agents._mail_maldoc_chain import run_maldoc_chain
from agentropix_mcp.agents._mail_parsers import (
    MailMessage,
    detect_format_with_hint,
    parse_eml,
    parse_msg,
    parse_pst_with_recovery,
)
from agentropix_mcp._env import get_int
from agentropix_mcp.server import ToolError, mcp_list_files
from agentropix_mcp.wrappers.email_headers import (
    email_header_matrix as _email_header_matrix,
)

logger = logging.getLogger(__name__)

_DEFAULT_MAX_BYTES = 50_000_000
_DEFAULT_MAX_MESSAGES = 5_000
_DEFAULT_LOOKALIKE_DISTANCE = 2

# Glob patterns the agent consults under ``image.parent`` to discover
# co-located mail artifacts (operator-extracted alongside the disk
# image). Patterns are conservative -- mailbox containers (.pst/.ost)
# and per-message exports (.msg/.eml) cover the four documented formats.
_DEFAULT_MAIL_PATTERNS: tuple[str, ...] = (
    "**/*.pst",
    "**/*.ost",
    "**/*.msg",
    "**/*.eml",
)


def _parse_one(
    content: bytes,
    *,
    source_path: str,
    spill_attachment: Callable[[bytes, str], Path] | None = None,
) -> tuple[list[MailMessage], str]:
    """Dispatch one file's bytes to the right parser.

    Returns ``(messages, format)``. Empty messages list means the file
    matched no recognised format; callers can drop it silently.

    ``spill_attachment`` (W-226 phishing-chain integration) is threaded
    into ``parse_pst`` / ``parse_msg`` so the agent layer can capture
    attachment bytes for downstream maldoc analysis.
    """
    fmt = detect_format_with_hint(content, source_path)
    if fmt == "eml":
        return [parse_eml(content)], fmt
    if fmt == "msg":
        return [parse_msg(
            content, Path(source_path), spill_attachment=spill_attachment,
        )], fmt
    if fmt in ("pst", "ost"):
        # SIFT-W-229: the recovery layer is a strict superset of
        # parse_pst — defaults to `recover="auto"`, which is a no-op
        # when pypff returns no `local_descriptors` skips and falls
        # back to `pffexport` when it does.
        return parse_pst_with_recovery(
            content, Path(source_path), spill_attachment=spill_attachment,
        ), fmt
    return [], fmt


def _findings_from_messages(
    messages: list[MailMessage],
    *,
    lookalike_distance: int,
) -> list[Finding]:
    """Run all five T1566 detectors over a parsed message list."""
    out: list[Finding] = []
    out.extend(detect_dangerous_attachments(messages))
    out.extend(detect_macro_documents(messages))
    out.extend(detect_link_mismatch(messages))
    out.extend(detect_oauth_phish(messages))
    out.extend(
        detect_lookalike_sender(messages, distance_floor=lookalike_distance)
    )
    return out


def _stub_deferral_finding(msg: MailMessage) -> Finding | None:
    """Build a low-confidence informational finding noting that a
    PST/OST/MSG file was detected but full parsing requires a dep that
    is not yet pinned. Returns ``None`` for messages that don't carry a
    deferral note (i.e. fully-parsed EML).
    """
    if not msg.parser_note:
        return None
    return Finding(
        source="mail.parser_deferred",
        confidence=0.3,
        description=(
            f"[T1566] {msg.source_format.upper()} mail container detected "
            f"but full parsing deferred: {msg.parser_note}"
        ),
        evidence=(
            f"path={msg.source_path} format={msg.source_format} "
            f"note={msg.parser_note}"
        ),
        evidence_dict={
            "source_path": msg.source_path,
            "source_format": msg.source_format,
            "parser_note": msg.parser_note,
        },
        mitre_attack="T1566",
        timestamp=Finding.now(),
    )


class MailAgent(SwarmAgent):
    """Detect T1566 (Phishing) indicators from PST/OST/MSG/EML artifacts."""

    name = "mail"
    completion_promise = "MAIL_TRIAGED"  # M8.3d

    def _read_max_bytes(self) -> int:
        return get_int(
            "AGENTROPIX_MAIL_MAX_BYTES",
            _DEFAULT_MAX_BYTES,
            floor=4_096,
            ceiling=500_000_000,
        )

    def _read_max_messages(self) -> int:
        return get_int(
            "AGENTROPIX_MAIL_MAX_MESSAGES",
            _DEFAULT_MAX_MESSAGES,
            floor=1,
            ceiling=100_000,
        )

    def _read_lookalike_distance(self) -> int:
        return get_int(
            "AGENTROPIX_MAIL_LOOKALIKE_DISTANCE",
            _DEFAULT_LOOKALIKE_DISTANCE,
            floor=1,
            ceiling=5,
        )

    def _run_on_text(
        self,
        content: str | bytes,
        source_path: str,
        *,
        spill_attachment: Callable[[bytes, str], Path] | None = None,
        collected_messages: list[MailMessage] | None = None,
    ) -> list[Finding]:
        """Parse + detect on raw mail bytes / text. Tests exercise this
        path directly; the live ``investigate`` flow funnels each
        discovered file through here.

        ``spill_attachment`` and ``collected_messages`` are populated by
        ``investigate()`` when the maldoc chain is enabled — the closure
        captures attachment bytes by sha256, and the list captures the
        parsed messages so the chain can iterate them after all files
        have been parsed.
        """
        if isinstance(content, str):
            content_bytes = content.encode("utf-8", errors="replace")
        else:
            content_bytes = content

        messages, fmt = _parse_one(
            content_bytes,
            source_path=source_path,
            spill_attachment=spill_attachment,
        )
        if not messages:
            return []

        max_msgs = self._read_max_messages()
        if len(messages) > max_msgs:
            messages = messages[:max_msgs]

        if collected_messages is not None:
            collected_messages.extend(messages)

        findings: list[Finding] = []

        # Stub-detected containers emit a deferral finding so operators
        # see the gap rather than a silent miss.
        for m in messages:
            deferral = _stub_deferral_finding(m)
            if deferral is not None:
                deferral.evidence_dict.setdefault("source_log", source_path)
                findings.append(deferral)

        findings.extend(
            _findings_from_messages(
                messages,
                lookalike_distance=self._read_lookalike_distance(),
            )
        )

        for f in findings:
            f.evidence_dict.setdefault("source_log", source_path)
        return findings

    def _carve_memory_mail(self, image: Path) -> list[Path]:
        """Carve EML sidecars from a memory image via the memory_mail_carve wrapper.

        Returns the list of carved .eml paths, or [] on ImportError / failure.
        """
        try:
            from agentropix_mcp.wrappers.memory_mail_carve import (  # noqa: PLC0415
                carve_emails_from_memory,
            )
        except ImportError as exc:
            logger.warning("MailAgent: memory_mail_carve unavailable: %s", exc)
            return []
        return carve_emails_from_memory(image)

    def _maldoc_chain_enabled(self) -> bool:
        """W-226: maldoc chain is on by default. Set
        ``AGENTROPIX_MAIL_MALDOC_CHAIN_DISABLE=1`` to skip the spill +
        post-pass and preserve pre-W-226 behaviour.
        """
        return get_int(
            "AGENTROPIX_MAIL_MALDOC_CHAIN_DISABLE",
            0, floor=0, ceiling=1,
        ) != 1

    @staticmethod
    def _safe_basename(name: str) -> str:
        """Strip path separators + non-portable chars from a spill basename.
        Filenames may originate from untrusted email attachments.
        """
        b = re.sub(r"[^A-Za-z0-9._-]", "_", Path(name).name)[:128]
        return b or "attachment"

    async def investigate(self, image: Path) -> list[Finding]:
        chain_enabled = self._maldoc_chain_enabled()
        spill_root: Path | None = None
        spill_paths_by_sha: dict[str, Path] = {}
        collected: list[MailMessage] | None = [] if chain_enabled else None
        spill_attachment: Callable[[bytes, str], Path] | None = None

        if chain_enabled:
            spill_root = Path(tempfile.mkdtemp(prefix="sift-maldoc-"))

            def spill_attachment(payload: bytes, suggested_name: str) -> Path:  # noqa: F811
                sha = hashlib.sha256(payload).hexdigest()
                cached = spill_paths_by_sha.get(sha)
                if cached is not None:
                    return cached
                dest = spill_root / f"{sha[:16]}_{self._safe_basename(suggested_name)}"
                dest.write_bytes(payload)
                spill_paths_by_sha[sha] = dest
                return dest

        try:
            return await self._investigate_inner(
                image,
                spill_attachment=spill_attachment,
                collected=collected,
                spill_paths_by_sha=spill_paths_by_sha,
                chain_enabled=chain_enabled,
            )
        finally:
            if spill_root is not None:
                shutil.rmtree(spill_root, ignore_errors=True)

    async def _investigate_inner(
        self,
        image: Path,
        *,
        spill_attachment: Callable[[bytes, str], Path] | None,
        collected: list[MailMessage] | None,
        spill_paths_by_sha: dict[str, Path],
        chain_enabled: bool,
    ) -> list[Finding]:
        if looks_like_memory(image):
            # Memory-only host: carve EML sidecars first, then run detectors
            # over the carved output directory.  No auth-failure matrix for
            # memory images — carved EMLs lack Authentication-Results headers.
            #
            # W-198 (Tier A.4 SANS roadmap): pre-check the
            # ``AGENTROPIX_MEM_MAIL_CARVE_BUDGET_MB`` budget before the
            # wrapper call so an over-budget image surfaces a Finding
            # rather than a silent [] return. base-mail-memory (17.4 GB)
            # exceeds the default 4 GB budget on SRL-2018, which is why
            # T1566 detection has been emitting 0 findings on the highest-
            # value mail host. The Finding tells the operator exactly which
            # env var to raise to unblock detection on that host.
            try:
                image_size_mb = image.stat().st_size // (1024 * 1024)
            except OSError:
                image_size_mb = 0
            budget_mb = get_int(
                "AGENTROPIX_MEM_MAIL_CARVE_BUDGET_MB",
                4096, floor=64, ceiling=32768,
            )
            carved = self._carve_memory_mail(image)
            if not carved and image_size_mb > budget_mb:
                suggested = image_size_mb + 2000
                return [Finding(
                    source="mail.memory_mail_carve",
                    confidence=0.5,
                    description=(
                        f"MailAgent skipped on memory image: "
                        f"{image_size_mb} MB exceeds "
                        f"AGENTROPIX_MEM_MAIL_CARVE_BUDGET_MB={budget_mb}. "
                        f"Set the env var to {suggested} or higher and re-run "
                        f"to enable T1566 phishing detection on this host."
                    ),
                    evidence=(
                        f"image_size_mb={image_size_mb} "
                        f"budget_mb={budget_mb} "
                        f"suggested_budget_mb={suggested}"
                    ),
                    mitre_attack="",
                )]
            if not carved:
                return []
            mail_paths = carved
            findings: list[Finding] = []
            max_bytes = self._read_max_bytes()
            for path in mail_paths:
                try:
                    content = self._read_bytes_capped(path, max_bytes)
                except OSError as exc:
                    logger.warning("MailAgent: cannot read %s: %s", path, exc)
                    continue
                if not content:
                    continue
                findings.extend(self._run_on_text(
                    content, str(path),
                    spill_attachment=spill_attachment,
                    collected_messages=collected,
                ))
            if chain_enabled and collected:
                findings.extend(await run_maldoc_chain(
                    collected, spill_paths_by_sha,
                ))
            return findings

        # Disk image path: run per-file detectors via mcp_list_files AND
        # run the header-matrix auth-failure detector over the corpus dir.
        # The two are independent: mcp_list_files may be blocked by Thymus
        # but the matrix scan reads directly via Python (no Thymus gate).
        mail_paths = await self._discover_mail_paths(image)
        findings = []
        max_bytes = self._read_max_bytes()
        for path in mail_paths:
            try:
                content = self._read_bytes_capped(path, max_bytes)
            except OSError as exc:
                logger.warning("MailAgent: cannot read %s: %s", path, exc)
                continue
            if not content:
                continue
            findings.extend(self._run_on_text(
                content, str(path),
                spill_attachment=spill_attachment,
                collected_messages=collected,
            ))

        if chain_enabled and collected:
            findings.extend(await run_maldoc_chain(
                collected, spill_paths_by_sha,
            ))

        # Auth-failure detection via header matrix (W-172).
        # Runs over image.parent so SPF/DKIM/DMARC from Authentication-Results
        # headers are available regardless of mcp_list_files results.
        try:
            matrix = _email_header_matrix(str(image.parent))
            if matrix.get("messages"):
                findings.extend(detect_auth_failure(matrix["messages"]))
        except Exception as exc:
            logger.debug("MailAgent: email_header_matrix error: %s", exc)

        return findings

    async def _discover_mail_paths(self, image: Path) -> list[Path]:
        """Enumerate co-located mail artifacts via ``mcp_list_files``."""
        base = image.parent
        out: list[Path] = []
        seen: set[str] = set()
        for pattern in _DEFAULT_MAIL_PATTERNS:
            try:
                result = await mcp_list_files(str(base), recursive=True, pattern=pattern)
            except Exception as exc:  # defensive — Thymus errors must not crash
                logger.debug("MailAgent list_files(%s) raised: %s", pattern, exc)
                continue
            if isinstance(result, ToolError):
                continue
            for p in result.paths:
                if p in seen:
                    continue
                seen.add(p)
                out.append(Path(p))
        return out

    @staticmethod
    def _read_bytes_capped(path: Path, max_bytes: int) -> bytes:
        with path.open("rb") as fh:
            return fh.read(max_bytes)
