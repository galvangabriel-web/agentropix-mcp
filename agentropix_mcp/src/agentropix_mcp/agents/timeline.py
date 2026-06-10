"""TimelineAgent — temporal-correlation specialist.

Calls Plaso (mcp_get_timeline) on disk images. Flags execution events
referencing scripting hosts and known LOLBins. The exhaustive event-rule
catalog lands in W3 — this skeleton emits one finding per matched event
so the contract is exercised end-to-end.

W-048 (M6): LOLBin-matched events are deduplicated by
``(keyword, message_prefix)`` by default so one command invoked N times
produces one finding rather than N.  Disable the dedup with
``AGENTROPIX_TIMELINE_DEDUP=0`` for debugging or when callers want to
count repetitions separately.  The prefix window is tuneable via
``AGENTROPIX_TIMELINE_DEDUP_MSG_CHARS`` (default 80, floor 20,
ceiling 500) — a narrow window merges aggressive "powershell.exe -enc …"
variants, a wide window keeps near-identical commands distinct.

W-050 P-A (M6.1): Parser set is now configurable via
``AGENTROPIX_TIMELINE_PARSERS`` (default includes winreg, prefetch,
scheduled_tasks, winjob in addition to filestat and winevtx).  The
agent emits findings for winreg Run-key persistence and prefetch
execution traces in addition to LOLBin events.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from agentropix_mcp.agents._base import Finding, SwarmAgent
from agentropix_mcp.agents._enrichment import enriched_finding
from agentropix_mcp.agents._evidence import looks_like_disk
from agentropix_mcp._env import get_float, get_int, get_str_set
from agentropix_mcp._trace import record as _trace_record
from agentropix_mcp.server import ToolError, mcp_get_timeline
from agentropix_mcp.wrappers.correlation import detect_sweep

logger = logging.getLogger(__name__)

_DEFAULT_LOLBIN_KEYWORDS: set[str] = {
    "powershell", "cmd.exe", "wscript", "cscript", "mshta", "regsvr32",
    "rundll32", "certutil", "bitsadmin",
    # W-052 AGENT-WIDEN (M6.2): schtasks is a LOLBin (LOLBAS project) used for
    # scheduled-task persistence (T1053.005). plaso winevtx/prefetch captures
    # schtasks.exe execution; inclusion here lets _check_timeline_source fire
    # T_SCHED_TASK so truth #1 (schtasks + scheduled) reaches cohit≥2.
    "schtasks",
}
# M6.3 W-050 event-window redesign: the plaso wrapper now applies per-
# parser sampling + priority filtering inside ``_parse_jsonl_events`` so
# high-signal events (4624, winreg Run, MFT timestomp, LOLBINs) survive
# a flood of datetime-earliest filestat rows.  Bumping the default cap
# from 500 → 2000 gives the sampler enough headroom to carry the priority
# allocation (200) plus per-parser round-robin across 6 default parsers
# at the new per-parser default (150) while still fitting well below
# TimelineAgent's AGENTROPIX_AGENT_FINDING_CAP (500).
_DEFAULT_MAX_EVENTS = 2000

# W-050 P-A: broadened default parser set to include winreg / prefetch /
# scheduled_tasks so the DC E01 beacon persistence and stager traces surface.
# W-054 (M6.2): mft added so timestomp anomalies surface for T1070.006 enrichment.
# W-062 (M6.6): filestat dropped from default. On a 12 GB Windows DC E01 the
# filestat parser produces millions of events, and the resulting plaso storage
# was too large for psort's `GetSortedEvents` SQLite sort spill — both
# `json_line` (TypeError) and the M6.5 `l2tcsv` fallback raised
# `sqlite3.OperationalError: database or disk is full` during _ExportEvents.
# Dropping filestat collapses storage 100×+ so psort's sort fits in tmp,
# unblocking the cohit≥2 recall pipeline. LOLBin signal from filestat is
# minor — winevtx security-audit messages still carry the same cmdline tokens.
_DEFAULT_TIMELINE_PARSERS = "winevtx,winreg,prefetch,winjob,mft"
_TIMELINE_PARSERS_FLOOR = 1
_TIMELINE_PARSERS_CEILING = 16

# W-191 / ARTIFACT-INVENTORY Gap A2: security-critical EVTX EIDs that the
# default dedup (``dedup_chars=80``) collapses into a single finding because
# target fields (TargetUserName/IpAddress) live ~250-400 chars deep in
# plaso's rendered winevtx message. ADR-005 calls for a verbose mode that
# preserves all matching events up to a cap (default 5000 per host).
#
# Each entry: (eid_string, mitre_technique, description_prefix, counter_label).
# MITRE mappings cite the technique most directly evidenced by the EID; some
# EIDs (e.g. 4624) could carry multiple TIDs, but we pick the canonical one.
# W-191 polish (session-wrap C1 forensic-accuracy critic):
#   * 4648 → T1078.002 (Domain Accounts): "Logon using explicit credentials"
#     is the canonical Pass-the-Hash / lateral-movement signal — domain-account
#     usage with alternate auth material. Bare T1078 lost the sub-technique
#     specificity. (Could also pair with T1550.002, but T1078.002 is the most
#     direct one-to-one mapping for the EID.)
#   * 4732 → T1098.007 (Additional Local or Domain Groups): "Member added to
#     security-enabled local group" is the literal data source MITRE cites
#     for the .007 sub-technique.
_VERBOSE_EVTX_EIDS: list[tuple[str, str, str, str]] = [
    ("4624", "T1078",     "Logon",                              "evtx_4624_verbose"),
    ("4625", "T1110",     "Failed logon",                       "evtx_4625_verbose"),
    ("4634", "T1078",     "Logoff",                             "evtx_4634_verbose"),
    ("4647", "T1078",     "User-initiated logoff",              "evtx_4647_verbose"),
    ("4648", "T1078.002", "Logon using explicit credentials",   "evtx_4648_verbose"),
    ("4672", "T1078.003", "Special privileges assigned",        "evtx_4672_verbose"),
    ("4720", "T1136.001", "Account created",                    "evtx_4720_verbose"),
    ("4732", "T1098.007", "Member added to security-enabled grp","evtx_4732_verbose"),
    ("4697", "T1543.003", "Service installed (Security log)",   "evtx_4697_verbose"),
    ("4698", "T1053.005", "Scheduled task created",             "evtx_4698_verbose"),
    ("7045", "T1543.003", "Service installed (System log)",     "evtx_7045_verbose"),
]

_VERBOSE_EVTX_CAP_FLOOR = 100
_VERBOSE_EVTX_CAP_CEILING = 50000
_VERBOSE_EVTX_CAP_DEFAULT = 5000

# Minimum prefix chars for winreg/prefetch dedup (re-uses dedup_chars).
_WINREG_RUN_PATTERNS = ("\\run\\", "\\run\x5c", "currentversion\\run", "\\runonce\\")
_PREFETCH_SUFFIX = ".pf"

# W-106: tokens that identify implant-named values inside a Run-key Entries
# list. When any of these appear in the message body, the Run-key finding's
# description gets a "beacon-named entry: ..." prefix so cohit-based recall
# matches the technique-relevant evidence (the value name) rather than only
# the technique-label boilerplate ("Registry", path-substring "Run").
_WINREG_RUN_BEACON_TOKENS: tuple[str, ...] = (
    "beacon",
    "stager",
    "artifact",
    "implant",
)
# W-106: empty-Entries markers emitted by plaso winreg/windows_run when a
# Run-key path exists but carries no values. Findings derived from these
# events were passing recall on technique-label boilerplate alone — skip
# them rather than emit a low-signal finding.
_WINREG_RUN_EMPTY_MARKERS: tuple[str, ...] = ("(empty)", "entries: []")


def _winreg_run_signal(message: str) -> tuple[bool, list[str]]:
    """Inspect a winreg Run-key plaso message for entries and beacon tokens.

    Returns ``(has_entries, beacon_tokens)``. ``has_entries`` is False when
    plaso emitted an explicit empty-list marker (``Entries: []`` /
    ``(empty)``). ``beacon_tokens`` is the subset of
    ``_WINREG_RUN_BEACON_TOKENS`` present in the message body.
    """
    lo = message.lower()
    if any(marker in lo for marker in _WINREG_RUN_EMPTY_MARKERS):
        return False, []
    return True, [tok for tok in _WINREG_RUN_BEACON_TOKENS if tok in lo]

# M6.10 W-067: AppData staging detector constants (T1055 process injection).
# Executable-like extensions that have no business appearing in user AppData
# unless dropped by an implant stager.
_STAGING_EXTENSIONS: tuple[str, ...] = (".exe", ".dll", ".bin", ".ps1", ".bat")
# Path fragments that identify legitimate Windows system-generated AppData files
# — exclude these so the detector doesn't fire on Windows-managed directories.
_BENIGN_APPDATA_FRAGMENTS: tuple[str, ...] = (
    "lastalive",
    "system32",
    "windows\\assembly",
    "windows\\fonts",
    "microsoft\\windows\\recent",
    "microsoft\\windows\\start menu",
    "notificationstation",
    "connecteddevices",
)


def _read_parsers() -> str:
    """Read AGENTROPIX_TIMELINE_PARSERS with floor/ceiling guards, then
    apply the AGENTROPIX_PLASO_EXCLUDE_FAMILIES exclusion list (M8.4c).

    Returns a comma-separated parser string ready to pass to plaso.
    Falls back to _DEFAULT_TIMELINE_PARSERS on empty/invalid input.

    M8.4c — operators can up-front skip noisy parser families (e.g.
    ``filestat`` floods, ``userassist`` chatter, ``prefetch`` low-signal
    rows on a quiet system) by setting:

        AGENTROPIX_PLASO_EXCLUDE_FAMILIES=filestat,userassist

    The exclusion is a tactical lever for the Plaso two-pass sampler —
    excluding before parse beats sampling after parse on multi-year disks
    where the excluded family would dominate the per-parser deque budget.
    Excluded names are removed from the resolved parser list AFTER the
    floor/ceiling check so an over-aggressive exclusion that would push
    the count below the floor falls back to the default.
    """
    raw = os.environ.get("AGENTROPIX_TIMELINE_PARSERS", "").strip()
    if not raw:
        resolved = _DEFAULT_TIMELINE_PARSERS
    else:
        tokens = [t.strip() for t in raw.split(",") if t.strip()]
        if len(tokens) < _TIMELINE_PARSERS_FLOOR:
            logger.warning(
                "AGENTROPIX_TIMELINE_PARSERS parsed to %d parser(s); below floor %d,"
                " falling back to default: %s",
                len(tokens),
                _TIMELINE_PARSERS_FLOOR,
                _DEFAULT_TIMELINE_PARSERS,
            )
            resolved = _DEFAULT_TIMELINE_PARSERS
        elif len(tokens) > _TIMELINE_PARSERS_CEILING:
            logger.warning(
                "AGENTROPIX_TIMELINE_PARSERS parsed to %d parser(s); above ceiling %d,"
                " falling back to default: %s",
                len(tokens),
                _TIMELINE_PARSERS_CEILING,
                _DEFAULT_TIMELINE_PARSERS,
            )
            resolved = _DEFAULT_TIMELINE_PARSERS
        else:
            resolved = ",".join(tokens)

    # Apply M8.4c exclusion list. Strip leading/trailing whitespace per
    # token to tolerate "filestat , userassist".
    excl_raw = os.environ.get("AGENTROPIX_PLASO_EXCLUDE_FAMILIES", "").strip()
    if not excl_raw:
        return resolved
    excludes = {t.strip() for t in excl_raw.split(",") if t.strip()}
    kept = [t.strip() for t in resolved.split(",") if t.strip() and t.strip() not in excludes]
    if len(kept) < _TIMELINE_PARSERS_FLOOR:
        logger.warning(
            "AGENTROPIX_PLASO_EXCLUDE_FAMILIES would leave only %d parser(s);"
            " below floor %d, ignoring exclusion list",
            len(kept),
            _TIMELINE_PARSERS_FLOOR,
        )
        return resolved
    return ",".join(kept)


def _findings_from_sweep(report, image: Path) -> list[Finding]:
    """Extract findings from SMB sweep detection (T1021.002)."""
    out: list[Finding] = []
    for burst in report.bursts:
        out.append(
            Finding(
                source="timeline.sweep_detection",
                confidence=0.85,
                description=(
                    f"SMB share enumeration burst: {burst.src_ip} accessed "
                    f"{len(burst.target_shares)} shares in {burst.window_size_seconds}s"
                ),
                evidence=(
                    f"src_ip={burst.src_ip} shares={burst.event_count} "
                    f"window={burst.window_start}…{burst.window_end} "
                    f"target_shares={','.join(burst.target_shares[:5])}"
                    f"{'...' if len(burst.target_shares) > 5 else ''}"
                ),
                mitre_attack="T1021.002",
                timestamp=Finding.now(),
            )
        )
    return out


class TimelineAgent(SwarmAgent):
    name = "timeline"
    completion_promise = "TIMELINE_GENERATED"  # M8.3d

    def __init__(self, blackboard, *, max_events: int | None = None) -> None:
        super().__init__(blackboard)
        # Explicit kwarg wins; otherwise fall back to env-var-tunable default.
        self._max_events_override = max_events

    async def investigate(self, image: Path) -> list[Finding]:
        if not looks_like_disk(image):
            return []

        max_events = (
            self._max_events_override
            if self._max_events_override is not None
            else get_int(
                "AGENTROPIX_TIMELINE_MAX_EVENTS",
                _DEFAULT_MAX_EVENTS,
                floor=1,
                ceiling=100000,
            )
        )
        lolbins = get_str_set(
            "AGENTROPIX_TIMELINE_LOLBINS",
            _DEFAULT_LOLBIN_KEYWORDS,
        )
        lolbin_conf = get_float(
            "AGENTROPIX_TIMELINE_LOLBIN_CONFIDENCE",
            0.7,
            floor=0.0,
            ceiling=1.0,
        )

        dedup_enabled = bool(
            get_int("AGENTROPIX_TIMELINE_DEDUP", 1, floor=0, ceiling=1)
        )
        dedup_chars = get_int(
            "AGENTROPIX_TIMELINE_DEDUP_MSG_CHARS",
            80,
            floor=20,
            ceiling=500,
        )
        # W-A09: control truncation of msg field in evidence strings.
        # Default 600 chars captures TargetUserName/TargetDomainName/IpAddress
        # in 4624 logon events (target fields appear ~250-400 chars deep).
        # Floor 80 keeps minimum diagnostic value; ceiling 4000 prevents
        # OOM on pathological event blobs.
        evidence_msg_chars = get_int(
            "AGENTROPIX_TIMELINE_EVIDENCE_MSG_CHARS",
            600,
            floor=80,
            ceiling=4000,
        )

        # W-191 / Gap A2: verbose EVTX mode. Default OFF preserves existing
        # dedup-collapse behaviour for callers who haven't opted in. When ON,
        # emit one finding per matching verbose-EID event up to ``verbose_cap``.
        verbose_evtx_enabled = bool(
            get_int("AGENTROPIX_EVTX_VERBOSE", 0, floor=0, ceiling=1)
        )
        verbose_evtx_cap = get_int(
            "AGENTROPIX_EVTX_VERBOSE_CAP",
            _VERBOSE_EVTX_CAP_DEFAULT,
            floor=_VERBOSE_EVTX_CAP_FLOOR,
            ceiling=_VERBOSE_EVTX_CAP_CEILING,
        )
        verbose_emitted = 0
        verbose_dropped = 0  # W-191 polish: count events dropped after cap binds
        verbose_cap_logged = False

        parsers = _read_parsers()

        result = await mcp_get_timeline(
            str(image), parsers=parsers, max_events=max_events
        )
        if isinstance(result, ToolError):
            # W-049: WRAPPER_TIMEOUT tag when plaso times out
            err_lower = result.error.lower()
            is_timeout = "timeout" in err_lower or "timed out" in err_lower
            desc = (
                f"WRAPPER_TIMEOUT: timeline timed out: {result.error}"
                if is_timeout
                else f"timeline failed: {result.error}"
            )
            if is_timeout:
                logger.warning(
                    "TimelineAgent WRAPPER_TIMEOUT for image=%s: %s", image, result.error
                )
            # W-060 persistence: even on hard ToolError we still push a
            # zero-shape ``trace.timeline.counters`` record so the report
            # schema stays stable — downstream readers can rely on the
            # counters field being present on every timeline run.
            _trace_record(
                "trace.timeline.counters",
                0.0,
                "jsonl_rows=0 priority_hits=0 events_recv=0 detectors_fired=0"
                f" wrapper_error={result.error[:80]}",
                counters={
                    "jsonl_rows_read": 0,
                    "priority_hits_by_family": {
                        "4624": 0, "winreg_run": 0,
                        "mft_timestomp": 0, "lolbin": 0,
                    },
                    "parser_deque_sizes": {},
                    "events_received_by_agent": 0,
                    "detectors_fired_by_id": {
                        "4624_detector": 0,
                        "winreg_run_detector": 0,
                        "prefetch_detector": 0,
                        "mft_timestomp_detector": 0,
                        "lolbin_detector": 0,
                        "appdata_staging_detector": 0,
                    },
                    "wrapper_error": result.error[:200],
                },
            )
            return [
                Finding(
                    source="timeline.plaso",
                    confidence=0.0,
                    description=desc,
                    evidence=f"image={image}",
                )
            ]

        # W-060 persistence: soft-failure TimelineEvents carries
        # ``wrapper_error`` + zero counters when psort timed out.  Emit
        # the WRAPPER_TIMEOUT finding AND flow through to the counters
        # trace record below so report.json preserves both signals.
        wrapper_error = getattr(result, "wrapper_error", "") or ""
        if wrapper_error:
            logger.warning(
                "TimelineAgent WRAPPER_TIMEOUT for image=%s: %s",
                image,
                wrapper_error,
            )
            findings_head: list[Finding] = [
                Finding(
                    source="timeline.plaso",
                    confidence=0.0,
                    description=(
                        f"WRAPPER_TIMEOUT: timeline timed out: {wrapper_error}"
                    ),
                    evidence=f"image={image}",
                )
            ]
        else:
            findings_head = []

        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()

        # W-060 instrumentation — count events handed to the agent and
        # which detectors fire for each event so H3 (sampler emits but
        # detectors silently skip) becomes observable.  Initialised with
        # the four detector IDs at zero so downstream trace consumers
        # always see a stable shape.
        events_received_by_agent = len(result.events)
        detectors_fired_by_id = {
            "4624_detector": 0,
            "winreg_run_detector": 0,
            "prefetch_detector": 0,
            "mft_timestomp_detector": 0,
            "lolbin_detector": 0,
            "appdata_staging_detector": 0,
        }

        for event in result.events:
            msg = (event.message or "").lower()
            parser = (event.parser or "").lower()

            # --- LOLBin path (filestat / winevtx) ---
            hit = next((kw for kw in lolbins if kw in msg), None)
            if hit is not None:
                if dedup_enabled:
                    key = (hit, msg[:dedup_chars])
                    if key in seen:
                        continue
                    seen.add(key)
                raw_finding = Finding(
                    source="timeline.plaso",
                    confidence=lolbin_conf,
                    description=f"LOLBin in timeline: {hit}",
                    evidence=f"datetime={event.datetime} parser={event.parser} msg={(event.message or '')[:evidence_msg_chars]}",
                    timestamp=event.datetime or Finding.now(),
                    mitre_attack="T1059",
                )
                findings.append(enriched_finding(raw_finding))
                detectors_fired_by_id["lolbin_detector"] += 1
                continue

            # --- W-050 P-A: winreg Run-key persistence path ---
            if "winreg" in parser:
                msg_lower = msg
                is_run_key = any(pat in msg_lower for pat in _WINREG_RUN_PATTERNS)
                if is_run_key:
                    has_entries, beacon_tokens = _winreg_run_signal(
                        event.message or ""
                    )
                    if not has_entries:
                        continue
                    if dedup_enabled:
                        key = ("winreg_run", msg[:dedup_chars])
                        if key in seen:
                            continue
                        seen.add(key)
                    raw_msg = (event.message or "")[:160]
                    if beacon_tokens:
                        token_list = ",".join(sorted(set(beacon_tokens)))
                        description = (
                            f"Registry Run key write (beacon-named entry: "
                            f"{token_list}): {raw_msg}"
                        )
                    else:
                        description = f"Registry Run key write: {raw_msg}"
                    raw_finding = Finding(
                        source="timeline.plaso",
                        confidence=lolbin_conf,
                        description=description,
                        evidence=(
                            f"datetime={event.datetime} parser={event.parser}"
                            f" msg={(event.message or '')[:evidence_msg_chars]}"
                        ),
                        timestamp=event.datetime or Finding.now(),
                        mitre_attack="T1547.001",
                    )
                    findings.append(enriched_finding(raw_finding))
                    detectors_fired_by_id["winreg_run_detector"] += 1
                continue

            # --- W-050 P-A: prefetch execution trace path ---
            if "prefetch" in parser:
                if _PREFETCH_SUFFIX in msg or ".pf" in (event.display_name or "").lower():
                    if dedup_enabled:
                        key = ("prefetch", msg[:dedup_chars])
                        if key in seen:
                            continue
                        seen.add(key)
                    raw_finding = Finding(
                        source="timeline.plaso",
                        confidence=lolbin_conf,
                        description=f"Prefetch execution trace: {(event.message or '')[:160]}",
                        evidence=(
                            f"datetime={event.datetime} parser={event.parser}"
                            f" display={event.display_name or ''}"
                            f" msg={(event.message or '')[:evidence_msg_chars]}"
                        ),
                        timestamp=event.datetime or Finding.now(),
                        mitre_attack="T1059",
                    )
                    findings.append(enriched_finding(raw_finding))
                    detectors_fired_by_id["prefetch_detector"] += 1
                continue

            # --- W-191 / Gap A2: verbose EVTX detector (opt-in via env) ---
            # When enabled, emit one finding per matching security-critical
            # EID — bypassing the global dedup that otherwise collapses all
            # 4624 events into a single finding. Cap at ``verbose_evtx_cap``
            # to bound report size. Once the cap binds, drop remaining
            # verbose-EID events (don't fall through to the legacy 4624
            # detector — that would mix one collapsed finding with the
            # 5000 verbose ones and confuse operators reading the report).
            # Operators who want more events should raise the cap.
            if verbose_evtx_enabled and "winevtx" in parser:
                verbose_match = None
                for eid_str, mitre, desc_prefix, counter_label in _VERBOSE_EVTX_EIDS:
                    if eid_str in msg:
                        verbose_match = (eid_str, mitre, desc_prefix, counter_label)
                        break
                if verbose_match is not None:
                    if verbose_emitted < verbose_evtx_cap:
                        eid_str, mitre, desc_prefix, counter_label = verbose_match
                        raw_finding = Finding(
                            source="timeline.plaso",
                            confidence=lolbin_conf,
                            description=(
                                f"{desc_prefix} EventID {eid_str}: "
                                f"{(event.message or '')[:120]}"
                            ),
                            evidence=(
                                f"datetime={event.datetime} parser={event.parser}"
                                f" msg={(event.message or '')[:evidence_msg_chars]}"
                            ),
                            timestamp=event.datetime or Finding.now(),
                            mitre_attack=mitre,
                        )
                        findings.append(enriched_finding(raw_finding))
                        detectors_fired_by_id[counter_label] = (
                            detectors_fired_by_id.get(counter_label, 0) + 1
                        )
                        verbose_emitted += 1
                    else:
                        # W-191 cap bound — drop the event and tally so the
                        # final log carries an honest dropped-count.
                        verbose_dropped += 1
                        if not verbose_cap_logged:
                            logger.warning(
                                "AGENTROPIX_EVTX_VERBOSE_CAP=%d bound at "
                                "first additional verbose-EID match; further "
                                "matches will be dropped silently. Final "
                                "dropped count logged at end of iteration. "
                                "Raise the cap to capture more.",
                                verbose_evtx_cap,
                            )
                            verbose_cap_logged = True
                    continue

            # --- W-050 P-B: winevtx EventID 4624 logon detection ---
            if "winevtx" in parser and "4624" in msg:
                if dedup_enabled:
                    key = ("evtx_4624", msg[:dedup_chars])
                    if key in seen:
                        continue
                    seen.add(key)
                raw_finding = Finding(
                    source="timeline.plaso",
                    confidence=lolbin_conf,
                    description=f"Logon event EventID 4624: {(event.message or '')[:120]}",
                    evidence=(
                        f"datetime={event.datetime} parser={event.parser}"
                        f" msg={(event.message or '')[:evidence_msg_chars]}"
                    ),
                    timestamp=event.datetime or Finding.now(),
                    mitre_attack="T1078",
                )
                findings.append(enriched_finding(raw_finding))
                detectors_fired_by_id["4624_detector"] += 1
                continue

            # --- W-054 (M6.2): MFT timestomp anomaly detection ---
            # W-066 (M6.8): widened to inspect ``timestamp_desc`` too.  On
            # live DC E01 runs, priority_hits_by_family.mft_timestomp was 0
            # across 13.8M l2tcsv rows (P0-3.4 trace.counters) despite 150
            # MFT events reaching the per-parser deque — plaso's MFT parser
            # emits the modified-time signal in the l2tcsv ``type`` column
            # (col 6 → ``TimelineEvent.timestamp_desc``), not in ``desc``
            # (col 10 → ``message``).  The msg body carries the path /
            # attribute / inode; the modified-time semantic lives only in
            # timestamp_desc values like ``"Entry Modified"`` or
            # ``"Modification Time"``.  We still never fabricate the signal
            # — the raw plaso event itself must say it.
            if "mft" in parser:
                ts_desc = (event.timestamp_desc or "").lower()
                has_signal = (
                    "modified" in msg
                    or "timestomp" in msg
                    or "modified" in ts_desc
                    or "modification" in ts_desc
                )
                if has_signal:
                    if dedup_enabled:
                        key = ("mft_timestomp", msg[:dedup_chars])
                        if key in seen:
                            continue
                        seen.add(key)
                    raw_finding = Finding(
                        source="timeline.plaso",
                        confidence=lolbin_conf,
                        description=f"MFT entry modified-time anomaly: {(event.message or '')[:120]}",
                        evidence=(
                            f"datetime={event.datetime} parser={event.parser}"
                            f" ts_desc={event.timestamp_desc or ''}"
                            f" msg={(event.message or '')[:evidence_msg_chars]}"
                        ),
                        timestamp=event.datetime or Finding.now(),
                        mitre_attack="T1070.006",
                    )
                    findings.append(enriched_finding(raw_finding))
                    detectors_fired_by_id["mft_timestomp_detector"] += 1

                # --- M6.10 W-067: AppData staging detector (T1055) ---
                # Cobalt Strike beacon stagers drop DLLs/binaries into user
                # AppData before reflective DLL injection. The MFT records the
                # file creation; we detect the pattern here — no second plaso
                # run required. Evidence terms are grounded in the raw plaso
                # path hint; "beacon=suspected" reflects the heuristic, not a
                # YARA match (difficulty=yara_hit is the demo target; this is
                # the disk-only approximation).
                msg_full = event.message or ""
                msg_full_lower = msg_full.lower()
                in_user_appdata = (
                    ("\\users\\" in msg_full_lower or "/users/" in msg_full_lower)
                    and "appdata" in msg_full_lower
                )
                if in_user_appdata:
                    has_staging_ext = any(
                        ext in msg_full_lower for ext in _STAGING_EXTENSIONS
                    )
                    is_benign = any(
                        frag in msg_full_lower for frag in _BENIGN_APPDATA_FRAGMENTS
                    )
                    if has_staging_ext and not is_benign:
                        staging_key = ("appdata_staging", msg[:dedup_chars])
                        if not dedup_enabled or staging_key not in seen:
                            if dedup_enabled:
                                seen.add(staging_key)
                            staging_finding = Finding(
                                source="timeline.plaso",
                                confidence=0.75,
                                description=(
                                    "Suspected beacon injection staging: "
                                    f"executable dropped in AppData — {msg_full[:80]}"
                                ),
                                evidence=(
                                    f"beacon=suspected AppData={msg_full[:120]}"
                                    f" injection=staging"
                                    f" datetime={event.datetime} parser={event.parser}"
                                ),
                                timestamp=event.datetime or Finding.now(),
                                mitre_attack="T1055",
                            )
                            findings.append(enriched_finding(staging_finding))
                            detectors_fired_by_id["appdata_staging_detector"] += 1

        # W-A06: Wire detect_sweep into per-host pipeline for SMB enumeration
        # burst detection (T1021.002). Only applicable to disk images with Security.evtx.
        if image.suffix.lower() == ".e01":
            try:
                sweep_report = await detect_sweep(
                    image, window_seconds=5.0, min_shares_per_window=3, timeout=300
                )
                findings.extend(_findings_from_sweep(sweep_report, image))
            except Exception as exc:
                logger.warning("detect_sweep failed for %s: %s", image, exc)

        # W-060 instrumentation — emit a single trace record carrying both
        # the wrapper-side sampler counters and the agent-side detector
        # counters so ``trace.tool_calls`` in ``report.json`` tells the
        # full H1/H2/H3 story at the wrapper→agent boundary.  The record
        # is additive (pushed via the existing ``record()`` helper) and
        # is a no-op if no trace scope is active.
        sampler_rows = getattr(result, "jsonl_rows_read", 0)
        sampler_priority = dict(
            getattr(result, "priority_hits_by_family", {}) or {}
        )
        sampler_deque = dict(
            getattr(result, "parser_deque_sizes", {}) or {}
        )
        # W-191 polish: surface the final dropped-count when the verbose cap
        # bound during this iteration. The per-event WARN at first-drop has
        # already fired; this is the honest end-of-iteration tally.
        if verbose_dropped > 0:
            logger.warning(
                "W-191 verbose-EID iteration summary: cap=%d emitted=%d "
                "dropped=%d. Raise AGENTROPIX_EVTX_VERBOSE_CAP to capture more.",
                verbose_evtx_cap,
                verbose_emitted,
                verbose_dropped,
            )
        summary = (
            f"jsonl_rows={sampler_rows} "
            f"priority_hits={sum(sampler_priority.values())} "
            f"events_recv={events_received_by_agent} "
            f"detectors_fired={sum(detectors_fired_by_id.values())}"
        )
        counters_payload: dict = {
            "jsonl_rows_read": sampler_rows,
            "priority_hits_by_family": sampler_priority,
            "parser_deque_sizes": sampler_deque,
            "events_received_by_agent": events_received_by_agent,
            "detectors_fired_by_id": detectors_fired_by_id,
            # W-197: verbose EVTX telemetry (Tier A.2 from SANS roadmap).
            # When AGENTROPIX_EVTX_VERBOSE=1, surface the per-host cap state
            # so operators sizing the cap have machine-readable evidence
            # rather than only the end-of-iteration log line.
            "verbose_evtx": {
                "enabled": bool(verbose_evtx_enabled),
                "cap": verbose_evtx_cap if verbose_evtx_enabled else 0,
                "emitted": verbose_emitted,
                "dropped": verbose_dropped,
            },
        }
        if wrapper_error:
            counters_payload["wrapper_error"] = wrapper_error[:200]
        _trace_record(
            "trace.timeline.counters",
            0.0,
            summary,
            counters=counters_payload,
        )

        # W-060 persistence: prepend the soft-failure WRAPPER_TIMEOUT
        # finding if plaso returned the wrapper_error tag so callers
        # still see the "something broke" signal at the findings layer.
        return findings_head + findings
