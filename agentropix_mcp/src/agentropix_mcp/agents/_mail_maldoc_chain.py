"""W-226 phishing-chain integration: drive ``analyze_maldoc()`` against
attachments spilled by mail-format parsers and translate the resulting
``MacroReport`` into ``Finding`` rows.

The chain runs as a post-processing pass over the parsed ``MailMessage``
list produced by ``parse_pst`` / ``parse_msg``, keyed against the
``sha256 → Path`` mapping built by the ``spill_attachment`` callback
that the agent layer threads into each parser.

Decoupled from ``mail.py`` so it is unit-testable in isolation.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TYPE_CHECKING

from agentropix_mcp.agents._base import Finding
from agentropix_mcp.agents._mail_parsers import MailMessage
from agentropix_mcp._env import get_float, get_int

if TYPE_CHECKING:
    from agentropix_mcp.wrappers.maldoc import MacroReport

logger = logging.getLogger(__name__)


# Mail-attachment-facing subset of `analyze_maldoc`'s accepted suffixes.
# .ole and .bin are deliberately excluded — they false-positive on
# benign payloads not actually carrying Office macros.
_MALDOC_EXT: frozenset[str] = frozenset({
    ".doc", ".docm", ".docx", ".dotm",
    ".xls", ".xlsm", ".xlsx", ".xlam",
    ".ppt", ".pptm", ".pptx",
    ".rtf",
})

_PER_ATT_TIMEOUT_ENV = "AGENTROPIX_MAIL_MALDOC_PER_ATT_TIMEOUT_S"
_MAX_ATT_ENV = "AGENTROPIX_MAIL_MALDOC_MAX_ATT"


def _maldoc_extension(filename: str) -> str:
    if not filename or "." not in filename:
        return ""
    return ("." + filename.rsplit(".", 1)[1]).lower()


def _confidence_for(report: MacroReport) -> float:
    """Stack signals: IoCs > auto-exec > obfuscation > macro-present."""
    has_ioc = bool(report.iocs)
    has_auto = bool(report.auto_exec_candidates)
    has_obf = bool(report.obfuscation_hints)
    if has_ioc and has_auto and has_obf:
        return 0.95
    if has_ioc and has_auto:
        return 0.85
    if has_ioc:
        return 0.70
    if has_auto and has_obf:
        return 0.65
    if has_auto:
        return 0.55
    if report.is_macro_enabled:
        return 0.40
    return 0.0


def _findings_from_report(
    report: MacroReport, *, msg: MailMessage, att_filename: str
) -> list[Finding]:
    """Translate one MacroReport into Findings. Schema mirrors PLAN §9.2.1."""
    out: list[Finding] = []
    conf = _confidence_for(report)
    auto = report.auto_exec_candidates[0] if report.auto_exec_candidates else None
    first_obf = report.obfuscation_hints[0] if report.obfuscation_hints else None

    for ioc in report.iocs:
        out.append(Finding(
            source="mail.macro_ioc",
            confidence=conf,
            description=(
                f"[T1566.001] Macro IoC ({ioc.type}) extracted from "
                f"'{att_filename}' attached to '{msg.subject[:80]}' "
                f"— value={ioc.value[:200]}"
            ),
            evidence=(
                f"attachment={att_filename} ioc_type={ioc.type} "
                f"ioc_value={ioc.value[:200]} auto_exec={auto or 'none'} "
                f"obfuscation={','.join(report.obfuscation_hints) or 'none'}"
            ),
            evidence_dict={
                "source_path": msg.source_path,
                "attachment_filename": att_filename,
                "attachment_sha256": report.sha256,
                "macro_stream": ioc.source,
                "ioc_type": ioc.type,
                "ioc_value": ioc.value,
                "obfuscation_class": first_obf,
                "auto_exec_trigger": auto,
                "confidence": conf,
                "mitre_technique": "T1566.001",
                "parser_note": report.parser_note,
            },
            mitre_attack="T1566.001",
            timestamp=Finding.now(),
        ))

    # Macro existed but produced no IoCs — still surface so the operator
    # sees the chain executed. Auto-exec / obfuscation by themselves are
    # signal even without a concrete URL/IP.
    if report.is_macro_enabled and not report.iocs:
        out.append(Finding(
            source="mail.macro_present",
            confidence=conf,
            description=(
                f"[T1566.001] Macro-enabled '{att_filename}' parsed; "
                f"no IoCs extracted (auto_exec={auto or 'none'}, "
                f"obfuscation={','.join(report.obfuscation_hints) or 'none'})"
            ),
            evidence=(
                f"attachment={att_filename} sha256={report.sha256[:16]} "
                f"macros={len(report.macros)} auto_exec={auto or 'none'} "
                f"obfuscation={','.join(report.obfuscation_hints) or 'none'}"
            ),
            evidence_dict={
                "source_path": msg.source_path,
                "attachment_filename": att_filename,
                "attachment_sha256": report.sha256,
                "macro_count": len(report.macros),
                "auto_exec_trigger": auto,
                "obfuscation_class": first_obf,
                "confidence": conf,
                "mitre_technique": "T1566.001",
                "parser_note": report.parser_note,
            },
            mitre_attack="T1566.001",
            timestamp=Finding.now(),
        ))

    # Parser hit a wall (truncated OLE, no macro stream) — operator
    # should see the deferral, not silence.
    if report.parser_note and not report.iocs and not report.is_macro_enabled:
        out.append(Finding(
            source="mail.maldoc_deferred",
            confidence=0.25,
            description=(
                f"[T1566.001] Maldoc analysis deferred on '{att_filename}': "
                f"{report.parser_note}"
            ),
            evidence=(
                f"attachment={att_filename} sha256={report.sha256[:16]} "
                f"note={report.parser_note}"
            ),
            evidence_dict={
                "source_path": msg.source_path,
                "attachment_filename": att_filename,
                "attachment_sha256": report.sha256,
                "parser_note": report.parser_note,
                "mitre_technique": "T1566.001",
            },
            mitre_attack="T1566.001",
            timestamp=Finding.now(),
        ))

    return out


AnalyzeFn = Callable[..., Awaitable["MacroReport"]]


async def run_maldoc_chain(
    messages: list[MailMessage],
    spill_paths_by_sha: dict[str, Path],
    *,
    analyze_fn: AnalyzeFn | None = None,
) -> list[Finding]:
    """Run ``analyze_maldoc`` on every spilled attachment with a
    maldoc-class extension and a known sha256, dedup by sha256 across
    the entire message list.

    ``analyze_fn`` is dependency-injectable for tests. When ``None`` the
    function lazy-imports the real wrapper so callers that opt out via
    env-var pay zero oletools import cost.
    """
    if analyze_fn is None:
        from agentropix_mcp.wrappers.maldoc import (  # noqa: PLC0415
            analyze_maldoc as analyze_fn,
        )

    timeout_s = get_float(
        _PER_ATT_TIMEOUT_ENV, 30.0, floor=5.0, ceiling=300.0,
    )
    max_att = get_int(_MAX_ATT_ENV, 100, floor=1, ceiling=10_000)

    out: list[Finding] = []
    seen_sha: set[str] = set()
    analysed = 0

    for msg in messages:
        for att in msg.attachments:
            if att.content_hash is None:
                continue
            ext = _maldoc_extension(att.filename)
            if ext not in _MALDOC_EXT:
                continue
            if att.content_hash in seen_sha:
                continue
            spill_path = spill_paths_by_sha.get(att.content_hash)
            if spill_path is None or not spill_path.exists():
                continue
            if analysed >= max_att:
                logger.warning(
                    "Maldoc chain cap %d hit; remaining attachments skipped",
                    max_att,
                )
                break

            seen_sha.add(att.content_hash)
            analysed += 1
            try:
                report = await analyze_fn(spill_path, timeout=timeout_s)
            except (ValueError, TimeoutError) as exc:
                logger.warning(
                    "analyze_maldoc(%s) failed (%s) — emitting deferral",
                    spill_path, exc,
                )
                out.append(Finding(
                    source="mail.maldoc_deferred",
                    confidence=0.25,
                    description=(
                        f"[T1566.001] analyze_maldoc failed on "
                        f"'{att.filename}': {exc}"
                    ),
                    evidence=(
                        f"attachment={att.filename} "
                        f"sha256={att.content_hash[:16]} error={exc}"
                    ),
                    evidence_dict={
                        "source_path": msg.source_path,
                        "attachment_filename": att.filename,
                        "attachment_sha256": att.content_hash,
                        "parser_note": f"analyze_maldoc_failed: {exc}",
                        "mitre_technique": "T1566.001",
                    },
                    mitre_attack="T1566.001",
                    timestamp=Finding.now(),
                ))
                continue

            out.extend(
                _findings_from_report(
                    report, msg=msg, att_filename=att.filename,
                ),
            )

        if analysed >= max_att:
            break

    return out
