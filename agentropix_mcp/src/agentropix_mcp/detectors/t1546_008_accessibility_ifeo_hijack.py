"""T1546.008 -- Accessibility-binary IFEO Debugger hijack detector (W-204).

Two legs (per DESIGNS/W-204-design.md):

* **LEG-A (write):** parse the SOFTWARE hive's
  ``Image File Execution Options`` subkeys for a ``Debugger`` value whose
  target binary is in the accessibility-binary class
  (``sethc``, ``utilman``, ``osk``, ``narrator``, ``magnify``,
  ``displayswitch``, ``atbroker``, ``eventvwr``) AND whose Debugger path
  lives outside ``C:\\Windows\\System32\\`` / ``C:\\Windows\\SysWOW64\\``
  AND does not match the trusted-debugger allowlist (SHA-256 +
  Authenticode subject -- BOTH must match, per round-4 c1-F3 ticket-AC
  fix).
* **LEG-B (exec):** read W-203's ``MASTER-IOCS.json``
  ``process_tree_findings`` (top-level OR ``data["iocs"][*]`` items with
  ``kind == "process_tree_event"``) for the same accessibility binary on
  the same host within a configurable window.

Findings emitted (per AC#2):

``t1546_008_accessibility_ifeo_hijack.paired``       (HIGH)   -- write + exec correlated
``t1546_008_accessibility_ifeo_hijack.write_only``   (MEDIUM) -- LEG-A unpaired
``t1546_008_accessibility_ifeo_hijack.exec_only``    (MEDIUM) -- LEG-B unpaired
``t1546_008_accessibility_ifeo_hijack.skipped``      (0.0)    -- non-E01 input (W-083 coverage)
``t1546_008_accessibility_ifeo_hijack.write_error``  (0.0)    -- extract/regripper failed
``t1546_008_accessibility_ifeo_hijack.exec_indeterminate``    (0.0) -- W-203 MASTER-IOCS absent
``t1546_008_accessibility_ifeo_hijack.complete``     (0.0)    -- ran to completion, no signal
``t1546_008_accessibility_ifeo_hijack.error``        (0.0)    -- redactor failed fail-closed

Phase-0.5 corpus finding (2026-05-16): both SRL-2018 and SRL-2015 carry
ZERO IFEO ``Debugger`` writes on any host (rip.pl imagefile + regipy
walk verified). The detector therefore exits via ``.complete`` /
``.exec_indeterminate`` on the live corpora; positive-path validation
uses the TEST_PLAN \xa72.1.1 adversary-fixture carve-out (LOCAL-only).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pydantic import BaseModel, Field

from agentropix_mcp.agents._base import Finding, SwarmAgent
from agentropix_mcp.agents._evidence import looks_like_e01
from agentropix_mcp._env import get_int
from agentropix_mcp.server import (
    ToolError,
    mcp_extract_files,
)
from agentropix_mcp.security.redact import RedactionError, redact_finding

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Class-based predicate set + trusted-debugger allowlist
# --------------------------------------------------------------------------- #

ACCESSIBILITY_BINARIES: frozenset[str] = frozenset({
    "sethc", "utilman", "osk", "narrator",
    "magnify", "displayswitch", "atbroker", "eventvwr",
})

_SYSTEM32_PREFIXES: tuple[str, ...] = (
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
)


class TrustedDebugger(BaseModel):
    """One entry in the trusted-debugger allowlist.

    Both ``image_sha256`` and ``authenticode_subject`` must match the
    observed Debugger binary for the entry to short-circuit the rule
    (per round-4 c1-F3 fix: path-string alone is INSUFFICIENT).
    """

    name: str
    image_sha256: str  # lowercase 64-hex
    authenticode_subject: str


# v1 ships with an EMPTY allowlist (per design Q5: conservative-default).
# Operators extend via ``AGENTROPIX_IFEO_TRUSTED_DEBUGGER_ALLOWLIST_PATH``
# (env-loaded JSON list of TrustedDebugger objects). With an empty
# allowlist + missing Authenticode parser, every accessibility-binary
# Debugger write outside System32 fires the rule -- the safest default.
TRUSTED_DEBUGGERS: tuple[TrustedDebugger, ...] = ()


# --------------------------------------------------------------------------- #
# Data models -- one IFEO write, one exec event
# --------------------------------------------------------------------------- #


class IfeoWriteEvent(BaseModel):
    """One IFEO Debugger-value write extracted from the SOFTWARE hive."""

    host: str
    target_binary: str
    debugger_path: str
    debugger_path_normalized: str
    debugger_sha256: str = ""
    debugger_authenticode_subject: str = ""
    last_write_utc: str = ""
    source_artifact: str = ""


class AccessibilityExecEvent(BaseModel):
    """One accessibility-binary process execution observation."""

    host: str
    target_binary: str
    pid: int = 0
    parent_pid: int = 0
    command_line_redacted: str = ""
    image_path_normalized: str = ""
    timestamp_utc: str = ""
    timestamp_source: str = ""


# --------------------------------------------------------------------------- #
# Pure helpers (unit-testable on extracted real fixtures + adversary fixtures)
# --------------------------------------------------------------------------- #


def is_accessibility_binary(target: str) -> bool:
    """True iff ``target`` (case-insensitive, ``.exe`` stripped) is in
    :data:`ACCESSIBILITY_BINARIES`."""
    if not target:
        return False
    name = target.strip().lower()
    if name.endswith(".exe"):
        name = name[:-4]
    return name in ACCESSIBILITY_BINARIES


_ENVVAR_RE = re.compile(r"%([A-Za-z_][A-Za-z0-9_]*)%")


def normalize_debugger_path(raw: str) -> str:
    """Expand %SystemRoot%/%WinDir%, case-fold, backslash-normalise.

    Conservative substitution: only expands the two env vars Windows uses
    for IFEO targets. Other env-var references are stripped to their raw
    form lowercased -- enough to expose path traversal outside System32
    without inventing host-specific values.
    """
    if not raw:
        return ""
    expansions = {
        "systemroot": "c:\\windows",
        "windir": "c:\\windows",
        "programfiles": "c:\\program files",
        "programfiles(x86)": "c:\\program files (x86)",
        "programdata": "c:\\programdata",
    }

    def repl(m: re.Match[str]) -> str:
        return expansions.get(m.group(1).lower(), m.group(0))

    out = _ENVVAR_RE.sub(repl, raw)
    out = out.replace("/", "\\").lower().strip()
    # Strip surrounding quotes (some IFEO debugger values wrap in quotes).
    if len(out) >= 2 and out[0] == '"' and out[-1] == '"':
        out = out[1:-1]
    return out


def is_outside_system32(normalized_path: str) -> bool:
    """True iff ``normalized_path`` does NOT live under System32/SysWOW64."""
    if not normalized_path:
        return False
    return not any(normalized_path.startswith(p) for p in _SYSTEM32_PREFIXES)


def matches_trusted_debugger(
    *,
    image_sha256: str,
    authenticode_subject: str,
    allowlist: tuple[TrustedDebugger, ...] = TRUSTED_DEBUGGERS,
) -> bool:
    """True iff (sha256, subject) tuple matches an allowlist entry.

    BOTH fields must be non-empty AND match (round-4 c1-F3 fix). A blank
    SHA-256 (which is the v1 default because no Authenticode parser is
    wired) fails closed -- the rule fires.
    """
    if not image_sha256 or not authenticode_subject:
        return False
    sha = image_sha256.strip().lower()
    subj = authenticode_subject.strip()
    for entry in allowlist:
        if entry.image_sha256.strip().lower() == sha and entry.authenticode_subject.strip() == subj:
            return True
    return False


def _parse_iso_utc(s: str) -> datetime | None:
    if not s:
        return None
    try:
        # Tolerate the rip.pl "...Z" suffix as well as ISO 8601 with offset.
        if s.endswith("Z") and "+" not in s[:-1]:
            s = s[:-1] + "+00:00"
        # rip.pl emits "2020-01-15 12:34:56" (space separator + Z). Accept
        # either separator.
        s = s.replace(" ", "T", 1) if (len(s) > 10 and s[10] == " ") else s
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def correlate_write_to_exec(
    writes: list[IfeoWriteEvent],
    execs: list[AccessibilityExecEvent],
    *,
    window_sec: int,
    skew_tolerance_sec: int = 0,
) -> list[tuple[IfeoWriteEvent, AccessibilityExecEvent]]:
    """Pair (write, exec) where same host, same target, and the exec
    timestamp falls inside ``[write_ts, write_ts + window_sec + skew]``.

    Negative deltas (exec BEFORE write) are dropped. Boundary is inclusive
    on the right edge (per G3 spec).
    """
    pairs: list[tuple[IfeoWriteEvent, AccessibilityExecEvent]] = []
    budget = timedelta(seconds=window_sec + skew_tolerance_sec)
    for w in writes:
        w_target = w.target_binary.strip().lower().removesuffix(".exe")
        w_ts = _parse_iso_utc(w.last_write_utc)
        if w_ts is None:
            continue
        for e in execs:
            if e.host != w.host:
                continue
            e_target = e.target_binary.strip().lower().removesuffix(".exe")
            if e_target != w_target:
                continue
            e_ts = _parse_iso_utc(e.timestamp_utc)
            if e_ts is None:
                continue
            delta = e_ts - w_ts
            if delta < timedelta(0):
                continue
            if delta > budget:
                continue
            pairs.append((w, e))
    return pairs


# --------------------------------------------------------------------------- #
# rip.pl `imagefile` plugin output parser
# --------------------------------------------------------------------------- #
#
# Plugin source (verified at /usr/local/src/regripper/plugins/imagefile.pl)
# emits one section per IFEO root then one stanza per subkey that carries
# a non-empty ``Debugger`` (or ``CWDIllegalInDllSearch``) value:
#
#   Microsoft\Windows NT\CurrentVersion\Image File Execution Options
#   sethc.exe  LastWrite: 2020-01-15 12:34:56Z
#     Debugger             : C:\Windows\System32\cmd.exe
#     Auto                 : ...
#
# The parser collects ``(subkey_name, lastwrite, debugger_path)`` tuples;
# entries without a Debugger value are not emitted by the plugin so the
# parser only ever sees the actionable rows.


_RIP_HEADER_RE = re.compile(
    r"^Image File Execution Options(?P<wow>\b.*)?$",
    re.MULTILINE,
)
_RIP_SUBKEY_RE = re.compile(
    r"^(?P<subkey>\S+?\.exe)\s+LastWrite:\s+(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})Z\s*$",
    re.MULTILINE,
)
_RIP_DEBUGGER_RE = re.compile(
    r"^\s+Debugger\s*:\s*(?P<path>\S.*?)\s*$",
    re.MULTILINE,
)


def parse_rip_imagefile(
    rip_stdout: str,
    *,
    host: str,
    source_artifact: str,
) -> list[IfeoWriteEvent]:
    """Parse rip.pl ``imagefile`` plugin stdout into IfeoWriteEvent rows.

    Plugin only emits a stanza when a Debugger or CWDIllegalInDllSearch
    value exists. Stanzas without ``Debugger:`` are skipped (Auto-only
    entries don't carry a debugger payload). The parser is permissive on
    intra-stanza ordering: each subkey header collects the *next*
    ``  Debugger             : <value>`` line that appears before the
    next subkey header (or end-of-output), within the same IFEO section.
    """
    if not rip_stdout.strip():
        return []

    results: list[IfeoWriteEvent] = []
    subkey_matches = list(_RIP_SUBKEY_RE.finditer(rip_stdout))
    for idx, sm in enumerate(subkey_matches):
        start = sm.end()
        end = subkey_matches[idx + 1].start() if idx + 1 < len(subkey_matches) else len(rip_stdout)
        stanza = rip_stdout[start:end]
        debugger_m = _RIP_DEBUGGER_RE.search(stanza)
        if not debugger_m:
            continue
        raw = debugger_m.group("path").strip()
        ts_raw = sm.group("ts").strip()
        # Convert "2020-01-15 12:34:56Z" -> ISO 8601 UTC.
        iso = ts_raw.replace(" ", "T", 1) + "+00:00"
        normalized = normalize_debugger_path(raw)
        results.append(
            IfeoWriteEvent(
                host=host,
                target_binary=sm.group("subkey").strip(),
                debugger_path=raw,
                debugger_path_normalized=normalized,
                last_write_utc=iso,
                source_artifact=source_artifact,
            )
        )
    return results


# --------------------------------------------------------------------------- #
# W-203 MASTER-IOCS consumer for LEG-B
# --------------------------------------------------------------------------- #


_MASTER_IOCS_ENV = "AGENTROPIX_W203_MASTER_IOCS_PATH"
_MASTER_IOCS_RUN_DIR_ENV = "AGENTROPIX_W203_RUN_DIR"


def locate_master_iocs_for_host(host: str) -> list[dict] | None:
    """Resolve W-203 MASTER-IOCS output to host-scoped exec entries.

    Search order (design \xa73.1): explicit ``AGENTROPIX_W203_MASTER_IOCS_PATH``
    first, then ``AGENTROPIX_W203_RUN_DIR/MASTER-IOCS.json``. Returns
    ``None`` when neither env var is set or the file is unreadable;
    returns ``[]`` when the file exists but contains no entries for
    ``host``. The list contains raw dicts in either of the two surfaces
    the detector tolerates (top-level ``process_tree_findings`` OR
    ``data["iocs"][*]`` filtered to ``kind == "process_tree_event"``).
    """
    explicit = os.environ.get(_MASTER_IOCS_ENV, "").strip()
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    run_dir = os.environ.get(_MASTER_IOCS_RUN_DIR_ENV, "").strip()
    if run_dir:
        candidates.append(Path(run_dir) / "MASTER-IOCS.json")

    if not candidates:
        return None
    target: Path | None = None
    for c in candidates:
        if c.is_file():
            target = c
            break
    if target is None:
        return None

    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("W-204 MASTER-IOCS read failed %s: %s", target, exc)
        return None

    # Surface 1: top-level process_tree_findings.
    entries = data.get("process_tree_findings") if isinstance(data, dict) else None
    if not entries:
        # Surface 2: data["iocs"][*] filtered to kind == process_tree_event.
        iocs = data.get("iocs") if isinstance(data, dict) else None
        entries = []
        if isinstance(iocs, list):
            for item in iocs:
                if isinstance(item, dict) and item.get("kind") == "process_tree_event":
                    entries.append(item)

    if not isinstance(entries, list):
        return []
    host_lc = host.strip().lower()
    return [
        e for e in entries
        if isinstance(e, dict) and str(e.get("host", "")).strip().lower() == host_lc
    ]


def extract_accessibility_execs_from_master_iocs(
    process_tree_findings: list[dict],
    *,
    host: str,
) -> list[AccessibilityExecEvent]:
    """Filter W-203 process_tree entries to accessibility-binary execs."""
    out: list[AccessibilityExecEvent] = []
    host_lc = host.strip().lower()
    for raw in process_tree_findings:
        if not isinstance(raw, dict):
            continue
        if str(raw.get("host", "")).strip().lower() != host_lc:
            continue
        image_path = str(raw.get("image_path", "")).strip()
        cmdline = str(raw.get("command_line", "")).strip()
        # Resolve target_binary from image_path basename.
        base = image_path.replace("/", "\\").rsplit("\\", 1)[-1]
        if not is_accessibility_binary(base):
            # Fall back to command_line tokenisation.
            first_tok = cmdline.split()[0] if cmdline else ""
            tok_base = first_tok.replace("/", "\\").rsplit("\\", 1)[-1]
            if not is_accessibility_binary(tok_base):
                continue
            base = tok_base
        target = base.lower().removesuffix(".exe")
        out.append(
            AccessibilityExecEvent(
                host=host,
                target_binary=target,
                pid=int(raw.get("pid", 0) or 0),
                parent_pid=int(raw.get("parent_pid", 0) or 0),
                command_line_redacted=cmdline,  # caller redacts
                image_path_normalized=image_path.replace("/", "\\").lower(),
                timestamp_utc=str(raw.get("timestamp_utc", "")),
                timestamp_source=str(raw.get("timestamp_source", "")),
            )
        )
    return out


# --------------------------------------------------------------------------- #
# Finding builders
# --------------------------------------------------------------------------- #


_KEYWORD_TAIL = "ifeo accessibility sticky_keys t1546.008"


def _make_paired_finding(
    w: IfeoWriteEvent,
    e: AccessibilityExecEvent,
    *,
    host: str,
    window_sec: int,
) -> Finding:
    w_ts = _parse_iso_utc(w.last_write_utc)
    e_ts = _parse_iso_utc(e.timestamp_utc)
    delta_sec = int((e_ts - w_ts).total_seconds()) if (w_ts and e_ts) else 0
    return Finding(
        source="t1546_008_accessibility_ifeo_hijack.paired",
        confidence=0.95,
        description=(
            f"Accessibility-binary IFEO Debugger hijack confirmed "
            f"(T1546.008 sticky_keys): host={host} binary={w.target_binary} "
            f"debugger={w.debugger_path_normalized} exec_within={delta_sec}s"
        ),
        evidence=(
            f"host={host} target={w.target_binary} "
            f"debugger={w.debugger_path_normalized} "
            f"timestamp_source={e.timestamp_source} window={window_sec}s "
            f"{_KEYWORD_TAIL}"
        ),
        evidence_dict={
            "host": host,
            "target_binary": w.target_binary,
            "ifeo_write": w.model_dump(),
            "exec_event": e.model_dump(),
            "delta_seconds": delta_sec,
            "debugger_path_normalized": w.debugger_path_normalized,
            "debugger_outside_system32": is_outside_system32(w.debugger_path_normalized),
            "debugger_in_trusted_allowlist": matches_trusted_debugger(
                image_sha256=w.debugger_sha256,
                authenticode_subject=w.debugger_authenticode_subject,
            ),
            "window_sec": window_sec,
        },
        mitre_attack="T1546.008",
        timestamp=e.timestamp_utc or Finding.now(),
    )


def _make_write_only_finding(
    w: IfeoWriteEvent,
    *,
    host: str,
    window_sec: int,
    exec_data_status: str = "observed",
) -> Finding:
    return Finding(
        source="t1546_008_accessibility_ifeo_hijack.write_only",
        confidence=0.55,
        description=(
            f"Accessibility-binary IFEO Debugger value written but no "
            f"execution observed within window (T1546.008 staged backdoor): "
            f"host={host} binary={w.target_binary}"
        ),
        evidence=(
            f"host={host} target={w.target_binary} "
            f"debugger={w.debugger_path_normalized} window={window_sec}s "
            f"exec_data_status={exec_data_status} {_KEYWORD_TAIL}"
        ),
        evidence_dict={
            "host": host,
            "target_binary": w.target_binary,
            "ifeo_write": w.model_dump(),
            "exec_data_status": exec_data_status,
            "window_sec": window_sec,
        },
        mitre_attack="T1546.008",
        timestamp=w.last_write_utc or Finding.now(),
    )


def _make_exec_only_finding(
    e: AccessibilityExecEvent,
    *,
    host: str,
    window_sec: int,
) -> Finding:
    return Finding(
        source="t1546_008_accessibility_ifeo_hijack.exec_only",
        confidence=0.40,
        description=(
            f"Accessibility-binary execution observed without paired IFEO "
            f"Debugger write in window (T1546.008 possible legitimate launch "
            f"OR pre-existing write outside corpus window): host={host} "
            f"binary={e.target_binary}"
        ),
        evidence=(
            f"host={host} target={e.target_binary} pid={e.pid} "
            f"parent_pid={e.parent_pid} cmdline={e.command_line_redacted} "
            f"window={window_sec}s {_KEYWORD_TAIL}"
        ),
        evidence_dict={
            "host": host,
            "target_binary": e.target_binary,
            "exec_event": e.model_dump(),
            "window_sec": window_sec,
        },
        mitre_attack="T1546.008",
        timestamp=e.timestamp_utc or Finding.now(),
    )


# --------------------------------------------------------------------------- #
# Detector
# --------------------------------------------------------------------------- #


_RIP_TIMEOUT_DEFAULT_SEC = 120.0
_RIP_STDOUT_CAP_BYTES = 8 * 1024 * 1024  # 8 MiB -- IFEO output never approaches this


async def _run_rip_imagefile(hive_path: str) -> tuple[str, str]:
    """Invoke ``rip.pl -p imagefile -r <hive>`` and return ``(stdout, err)``.

    The detector uses this direct subprocess in place of the
    ``mcp_get_registry`` wrapper because the wrapper drops body content
    that rip.pl emits on stdout when the ``Launching`` header is on
    stderr (single-plugin ``-p`` mode -- see DECISION_LOG dev-w-204
    2026-05-16 entry). ``err`` is non-empty on rc ≠ 0 or timeout.
    """
    import shutil

    rip_path = shutil.which("rip.pl")
    if not rip_path:
        return "", "rip.pl not found on PATH"
    proc = await asyncio.create_subprocess_exec(
        rip_path, "-r", hive_path, "-p", "imagefile",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(), timeout=_RIP_TIMEOUT_DEFAULT_SEC,
        )
    except asyncio.TimeoutError:
        proc.kill()
        return "", f"rip.pl timed out after {_RIP_TIMEOUT_DEFAULT_SEC}s"
    if proc.returncode != 0:
        return "", f"rip.pl rc={proc.returncode}: {stderr_b.decode(errors='replace')[:200]}"
    stdout = stdout_b[:_RIP_STDOUT_CAP_BYTES].decode("utf-8", errors="replace")
    return stdout, ""


def _derive_host_from_image_path(image: Path) -> str:
    """Strip ``/cases/SRL-201X/`` prefix and ``.E01`` suffix to get a host
    label (per round-4 c1-F6 corpus-relative source_artifact mitigation)."""
    name = image.name
    if name.lower().endswith(".e01"):
        name = name[:-4]
    return name


def _redact_command_line(raw: str) -> tuple[str, RedactionError | None]:
    if not raw:
        return "", None
    try:
        redacted = redact_finding({"command_line": raw})
    except RedactionError as exc:
        return raw, exc
    return str(redacted.get("command_line", "")), None


class AccessibilityIfeoHijackDetector(SwarmAgent):
    """Detector for T1546.008 accessibility-binary IFEO Debugger hijack."""

    name = "t1546_008_accessibility_ifeo_hijack"
    completion_promise = "T1546_008_ACCESSIBILITY_IFEO_HIJACK_COMPLETE"

    async def investigate(self, image: Path) -> list[Finding]:
        if not looks_like_e01(image):
            return [
                Finding(
                    source="t1546_008_accessibility_ifeo_hijack.skipped",
                    confidence=0.0,
                    description=(
                        "AccessibilityIfeoHijackDetector skipped: "
                        f"{image.name} is not an E01 disk image"
                    ),
                    evidence=f"image={image} reason=non_e01_image",
                    timestamp=Finding.now(),
                )
            ]

        window_sec = get_int(
            "AGENTROPIX_IFEO_CORRELATION_WINDOW_SEC", 300, floor=60, ceiling=3600,
        )
        skew_tolerance_sec = get_int(
            "AGENTROPIX_IFEO_SKEW_TOLERANCE_SEC", 0, floor=0, ceiling=5,
        )
        debugger_hash_to = get_int(
            "AGENTROPIX_IFEO_DEBUGGER_HASH_TIMEOUT_SEC", 30, floor=5, ceiling=600,
        )
        host = _derive_host_from_image_path(image)

        # LEG-A -- IFEO writes from SOFTWARE hive.
        writes, write_error = await self._extract_writes(image, host, debugger_hash_to)

        # LEG-B -- accessibility execs from W-203 MASTER-IOCS.
        process_tree = locate_master_iocs_for_host(host)
        if process_tree is None:
            execs: list[AccessibilityExecEvent] = []
            exec_indeterminate = True
        else:
            execs = extract_accessibility_execs_from_master_iocs(
                process_tree, host=host,
            )
            exec_indeterminate = False

        # Redact command_lines before emission (R1 / design \xa78).
        redaction_error: RedactionError | None = None
        for e in execs:
            redacted, err = _redact_command_line(e.command_line_redacted)
            if err is not None:
                redaction_error = err
                break
            e.command_line_redacted = redacted

        if redaction_error is not None:
            return [
                Finding(
                    source="t1546_008_accessibility_ifeo_hijack.error",
                    confidence=0.0,
                    description=(
                        f"AccessibilityIfeoHijackDetector aborted: redactor "
                        f"failed fail-closed for host={host}: {redaction_error}"
                    ),
                    evidence=f"image={image} host={host} error={redaction_error}",
                    timestamp=Finding.now(),
                )
            ]

        # Correlate.
        pairs = correlate_write_to_exec(
            writes, execs,
            window_sec=window_sec,
            skew_tolerance_sec=skew_tolerance_sec,
        )

        out: list[Finding] = []
        paired_writes = {id(w) for w, _ in pairs}
        paired_execs = {id(e) for _, e in pairs}
        for w, e in pairs:
            out.append(_make_paired_finding(w, e, host=host, window_sec=window_sec))
        for w in writes:
            if id(w) in paired_writes:
                continue
            status = "indeterminate" if exec_indeterminate else "observed_no_match"
            out.append(_make_write_only_finding(
                w, host=host, window_sec=window_sec, exec_data_status=status,
            ))
        for e in execs:
            if id(e) in paired_execs:
                continue
            out.append(_make_exec_only_finding(e, host=host, window_sec=window_sec))

        if write_error:
            out.append(
                Finding(
                    source="t1546_008_accessibility_ifeo_hijack.write_error",
                    confidence=0.0,
                    description=(
                        f"AccessibilityIfeoHijackDetector LEG-A failed: "
                        f"{write_error}"
                    ),
                    evidence=f"image={image} host={host} error={write_error}",
                    timestamp=Finding.now(),
                )
            )

        if exec_indeterminate and not writes:
            out.append(
                Finding(
                    source="t1546_008_accessibility_ifeo_hijack.exec_indeterminate",
                    confidence=0.0,
                    description=(
                        f"AccessibilityIfeoHijackDetector LEG-B has no input: "
                        f"set AGENTROPIX_W203_MASTER_IOCS_PATH or "
                        f"AGENTROPIX_W203_RUN_DIR to a MASTER-IOCS.json"
                    ),
                    evidence=(
                        f"image={image} host={host} env_unset=true "
                        f"window={window_sec}s"
                    ),
                    timestamp=Finding.now(),
                )
            )

        if not out:
            # Ran to completion, neither leg produced any signal -- emit a
            # coverage-guard finding so W-083 sees the agent fired.
            out.append(
                Finding(
                    source="t1546_008_accessibility_ifeo_hijack.complete",
                    confidence=0.0,
                    description=(
                        f"AccessibilityIfeoHijackDetector scan complete: "
                        f"0 IFEO writes, 0 accessibility execs on host={host}"
                    ),
                    evidence=(
                        f"image={image} host={host} writes=0 execs=0 "
                        f"window={window_sec}s exec_indeterminate={exec_indeterminate}"
                    ),
                    timestamp=Finding.now(),
                )
            )
        return out

    async def _extract_writes(
        self,
        image: Path,
        host: str,
        debugger_hash_to: int,
    ) -> tuple[list[IfeoWriteEvent], str]:
        """Drive ``mcp_extract_files`` -> direct ``rip.pl -p imagefile`` shell-out.

        Returns ``(writes, error_msg)`` -- ``writes`` is the filtered list
        of IfeoWriteEvent rows that target accessibility binaries and live
        outside System32; ``error_msg`` is non-empty when LEG-A failed.

        The detector invokes rip.pl directly rather than via
        ``mcp_get_registry(plugin="imagefile")`` because the wrapper's
        merge order drops the plugin body when rip.pl emits it on stdout
        and the ``Launching`` header on stderr (live-verified
        2026-05-16 against base-wkstn-01-c-drive.SOFTWARE -- see
        DECISION_LOG dev-w-204 entry).

        Per design \xa73 step 4: when the trusted-debugger SHA-256 cannot be
        computed (no Authenticode parser in repo at v1), the allowlist
        match fails closed -- the write fires the rule.
        """
        with tempfile.TemporaryDirectory(prefix="agentropix-sift-w204-") as td:
            manifest = await mcp_extract_files(
                str(image),
                ["Windows/System32/config/SOFTWARE"],
                td,
            )
            if isinstance(manifest, ToolError):
                return [], f"extract_files: {manifest.error}"
            software_dest = ""
            for row in manifest.extracted:
                if Path(row.src_path).name.upper() == "SOFTWARE":
                    software_dest = row.dest
                    break
            if not software_dest:
                return [], "SOFTWARE hive not extracted"

            stdout_text, err = await _run_rip_imagefile(software_dest)
            if err:
                return [], err
            corpus_relative = self._corpus_relative_artifact(image)
            raw_writes = parse_rip_imagefile(
                stdout_text,
                host=host,
                source_artifact=corpus_relative,
            )

        filtered: list[IfeoWriteEvent] = []
        for w in raw_writes:
            if not is_accessibility_binary(w.target_binary):
                continue
            if not is_outside_system32(w.debugger_path_normalized):
                continue
            # Trusted-debugger allowlist (failing closed because SHA/subject
            # are empty in v1).
            if matches_trusted_debugger(
                image_sha256=w.debugger_sha256,
                authenticode_subject=w.debugger_authenticode_subject,
            ):
                continue
            filtered.append(w)
        # `debugger_hash_to` kept on signature so future Authenticode
        # enrichment honours the env-var timeout. Unused at v1.
        _ = debugger_hash_to
        return filtered, ""

    @staticmethod
    def _corpus_relative_artifact(image: Path) -> str:
        """``/cases/SRL-2018/base-rd-01.E01`` -> ``SRL-2018/base-rd-01.E01``."""
        try:
            rel = image.relative_to("/cases")
            return str(rel).replace("\\", "/")
        except ValueError:
            return image.name


__all__ = [
    "ACCESSIBILITY_BINARIES",
    "AccessibilityExecEvent",
    "AccessibilityIfeoHijackDetector",
    "IfeoWriteEvent",
    "TRUSTED_DEBUGGERS",
    "TrustedDebugger",
    "correlate_write_to_exec",
    "extract_accessibility_execs_from_master_iocs",
    "is_accessibility_binary",
    "is_outside_system32",
    "locate_master_iocs_for_host",
    "matches_trusted_debugger",
    "normalize_debugger_path",
    "parse_rip_imagefile",
]
