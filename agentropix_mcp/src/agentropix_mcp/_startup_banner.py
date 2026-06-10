"""W-088/W-089 — log the active env-var configuration at MCP startup.

Operators reported (W-088, W-089) that ``AGENTROPIX_HASHDEEP_TIMEOUT`` /
``AGENTROPIX_EXIFTOOL_TIMEOUT`` / ``AGENTROPIX_RATE_LIMIT`` (and a long
tail of other tunables) appeared hardcoded because nothing in the server
log surfaced them. They hit the default and assumed the value was baked
in.

This module fixes the UX gap by enumerating every ``AGENTROPIX_*`` env
var the codebase reads, looking up its current effective value (env
override or documented default), and emitting a single INFO-level
banner at server start. The list is hand-curated rather than discovered
at runtime so the banner stays accurate even when a wrapper hasn't been
imported yet — but each entry mirrors the resolver in the wrapper that
actually consumes it (default, floor, ceiling).

Discovery for new env vars: when adding a new ``AGENTROPIX_*`` knob,
add a matching ``EnvVarSpec`` to ``_KNOWN_ENV_VARS`` below so it shows
up in the banner. ``test_banner_lists_all_known_env_vars`` enforces a
sparseness floor of 5 entries; the bigger failure mode we want to
prevent is silently shipping an undocumented knob.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Module-level so callers (and tests) can introspect.
__all__ = [
    "EnvVarSpec",
    "build_active_configuration",
    "format_active_configuration",
    "log_active_configuration",
]


@dataclass(frozen=True)
class EnvVarSpec:
    """Single AGENTROPIX_* knob the server advertises at startup.

    ``default`` / ``floor`` / ``ceiling`` mirror the resolver call in
    the wrapper that actually reads the env var. ``None`` means
    "no guard at this end" (e.g. a free-form path or a string list).
    """

    name: str
    default: object
    floor: object | None = None
    ceiling: object | None = None
    description: str = ""


# Sourced by inspection of every ``get_int`` / ``get_float`` /
# ``get_str_set`` / ``os.environ.get`` call in ``src/agentropix_mcp/``.
# Order is roughly: server-level, then wrappers (alphabetical), then
# agents / trinity / memory. Adding a new knob? Append it here.
_KNOWN_ENV_VARS: tuple[EnvVarSpec, ...] = (
    # ----------------------------------------------------------------- #
    # MCP server boundary                                                #
    # ----------------------------------------------------------------- #
    EnvVarSpec(
        "AGENTROPIX_MCP_AUTH_TOKEN",
        default="",
        description="HTTP bearer token for MCP server (Phase 1 security fix; empty = disabled)",
    ),
    EnvVarSpec(
        "AGENTROPIX_RATE_LIMIT",
        default=60,
        floor=1,
        ceiling=10000,
        description="per-tool rate limit (calls/min)",
    ),
    EnvVarSpec(
        "AGENTROPIX_LOG_LEVEL",
        default="WARNING",
        description="root logger level (DEBUG/INFO/WARNING/ERROR)",
    ),
    EnvVarSpec(
        "AGENTROPIX_CONFIG",
        default="",
        description="explicit config-file override path",
    ),
    EnvVarSpec(
        "AGENTROPIX_AUDIT_LOG",
        default="",
        description="JSONL audit-log destination (empty = disabled)",
    ),
    EnvVarSpec(
        "AGENTROPIX_TRACE_RAW_MAX_BYTES",
        default=4096,
        floor=256,
        ceiling=1024 * 1024,
        description="per-call raw-output snapshot cap (bytes)",
    ),
    # ----------------------------------------------------------------- #
    # Thymus policy                                                      #
    # ----------------------------------------------------------------- #
    EnvVarSpec(
        "AGENTROPIX_THYMUS_ALLOWED_PREFIXES",
        default="",
        description="extra read-allowed prefixes (comma- or colon-separated)",
    ),
    EnvVarSpec(
        "AGENTROPIX_MAX_AUTO_PREFIXES",
        default=50,
        description="cap on auto-detected evidence prefixes",
    ),
    # ----------------------------------------------------------------- #
    # Wrappers — timeouts (sec)                                          #
    # ----------------------------------------------------------------- #
    EnvVarSpec(
        "AGENTROPIX_HASHDEEP_TIMEOUT",
        default=300,
        floor=5,
        ceiling=3600,
        description="hashdeep subprocess timeout (sec)",
    ),
    EnvVarSpec(
        "AGENTROPIX_EXIFTOOL_TIMEOUT",
        default=120,
        floor=5,
        ceiling=3600,
        description="exiftool subprocess timeout (sec)",
    ),
    EnvVarSpec(
        "AGENTROPIX_VOL3_TIMEOUT",
        default=120,
        floor=30,
        ceiling=None,
        description=(
            "volatility3 plugin timeout (sec) — used by all vol3 wrappers "
            "(W-142 consolidated AGENTROPIX_VOL_TIMEOUT into this name; "
            "legacy name still works but logs a deprecation warning)"
        ),
    ),
    EnvVarSpec(
        "AGENTROPIX_TSK_TIMEOUT",
        default=60,
        floor=5,
        ceiling=3600,
        description="TSK fls/ifind/icat timeout (sec)",
    ),
    EnvVarSpec(
        "AGENTROPIX_EWF_TIMEOUT",
        default=30,
        floor=5,
        ceiling=3600,
        description="ewfinfo subprocess timeout (sec)",
    ),
    EnvVarSpec(
        "AGENTROPIX_EWFMOUNT_TIMEOUT",
        default=30,
        floor=5,
        ceiling=300,
        description="ewfmount subprocess timeout (sec)",
    ),
    EnvVarSpec(
        "AGENTROPIX_FUSERMOUNT_TIMEOUT",
        default=10,
        floor=2,
        ceiling=60,
        description="fusermount unmount timeout (sec)",
    ),
    EnvVarSpec(
        "AGENTROPIX_REGRIPPER_TIMEOUT",
        default=60,
        floor=5,
        ceiling=3600,
        description="regripper subprocess timeout (sec)",
    ),
    EnvVarSpec(
        "AGENTROPIX_PREFETCH_TIMEOUT",
        default=60,
        floor=5,
        ceiling=3600,
        description="prefetch parser timeout (sec)",
    ),
    EnvVarSpec(
        "AGENTROPIX_AMCACHE_TIMEOUT",
        default=60,
        floor=5,
        ceiling=3600,
        description="amcache parser timeout (sec)",
    ),
    EnvVarSpec(
        "AGENTROPIX_SHIMCACHE_TIMEOUT",
        default=60,
        floor=5,
        ceiling=3600,
        description="shimcache parser timeout (sec)",
    ),
    EnvVarSpec(
        "AGENTROPIX_EVTX_TIMEOUT",
        default=180,
        floor=5,
        ceiling=3600,
        description="evtx parser timeout (sec)",
    ),
    EnvVarSpec(
        "AGENTROPIX_YARA_TIMEOUT",
        default=300,
        floor=5,
        ceiling=3600,
        description="yara scan timeout (sec)",
    ),
    EnvVarSpec(
        "AGENTROPIX_FOREMOST_TIMEOUT",
        default=300,
        floor=5,
        ceiling=86_400,
        description="foremost carve timeout (sec)",
    ),
    EnvVarSpec(
        "AGENTROPIX_BE_TIMEOUT",
        default=3600,
        floor=60,
        ceiling=86_400,
        description="bulk_extractor timeout (sec)",
    ),
    EnvVarSpec(
        "AGENTROPIX_STRINGS_TIMEOUT",
        default=120,
        floor=5,
        ceiling=3600,
        description="GNU strings timeout (sec)",
    ),
    EnvVarSpec(
        "AGENTROPIX_EXTRACT_TIMEOUT",
        default=60,
        floor=5,
        ceiling=3600,
        description="ifind+icat per-file timeout (sec)",
    ),
    EnvVarSpec(
        "AGENTROPIX_TASKS_LIST_TIMEOUT",
        default=60,
        floor=5,
        ceiling=3600,
        description="scheduled-tasks ifind/fls timeout (sec)",
    ),
    EnvVarSpec(
        "AGENTROPIX_PLASO_TIMEOUT",
        default="auto",
        description="plaso log2timeline timeout (sec; auto-scaled if unset)",
    ),
    EnvVarSpec(
        "AGENTROPIX_PLASO_TIMEOUT_CAP",
        default=7200,
        floor=30,
        ceiling=7200,
        description="plaso auto-scale ceiling (sec) [W-128, W-NEW-1 default bump 5400->7200]",
    ),
    EnvVarSpec(
        "AGENTROPIX_PSORT_TIMEOUT",
        default=5400,
        floor=30,
        ceiling=7200,
        description="plaso psort.py timeout (sec) [W-NEW-1 default bump 2700->5400]",
    ),
    EnvVarSpec(
        "AGENTROPIX_RECMD_TIMEOUT",
        default=120,
        floor=5,
        ceiling=3600,
        description="RECmd dotnet timeout (sec) [W-125]",
    ),
    EnvVarSpec(
        "AGENTROPIX_MFTECMD_TIMEOUT",
        default=300,
        floor=5,
        ceiling=3600,
        description="MFTECmd dotnet timeout (sec) [W-126]",
    ),
    EnvVarSpec(
        "AGENTROPIX_LECMD_TIMEOUT",
        default=120,
        floor=5,
        ceiling=3600,
        description="LECmd dotnet timeout (sec) [W-127]",
    ),
    # ----------------------------------------------------------------- #
    # Wrappers — caps                                                    #
    # ----------------------------------------------------------------- #
    EnvVarSpec(
        "AGENTROPIX_HASHDEEP_MAX_FILES",
        default=5000,
        floor=1,
        ceiling=500_000,
        description="hashdeep max files per call",
    ),
    EnvVarSpec(
        "AGENTROPIX_EXIFTOOL_MAX_FILES",
        default=2000,
        floor=1,
        ceiling=200_000,
        description="exiftool max files per call",
    ),
    EnvVarSpec(
        "AGENTROPIX_FOREMOST_MAX_ENTRIES",
        default=5000,
        floor=1,
        ceiling=1_000_000,
        description="foremost max audit entries returned",
    ),
    EnvVarSpec(
        "AGENTROPIX_BE_MAX_FEATURES",
        default=1000,
        floor=1,
        ceiling=1_000_000,
        description="bulk_extractor max features per recorder",
    ),
    EnvVarSpec(
        "AGENTROPIX_EVTX_MAX_EVENTS",
        default=1000,
        floor=1,
        ceiling=100_000,
        description="evtx max events returned",
    ),
    EnvVarSpec(
        "AGENTROPIX_PLASO_MAX_EVENTS",
        default=500,
        floor=1,
        ceiling=100_000,
        description="plaso max post-sampler events",
    ),
    EnvVarSpec(
        "AGENTROPIX_PLASO_PRIORITY_BUDGET",
        default=200,
        description="plaso priority-parser sampler budget",
    ),
    EnvVarSpec(
        "AGENTROPIX_PLASO_PER_PARSER_BUDGET",
        default=150,
        description="plaso per-parser event budget",
    ),
    EnvVarSpec(
        "AGENTROPIX_STRINGS_MAX_RESULTS",
        default=1000,
        floor=1,
        ceiling=1_000_000,
        description="GNU strings max results returned",
    ),
    EnvVarSpec(
        "AGENTROPIX_LIST_FILES_MAX_RESULTS",
        default=10000,
        floor=1,
        ceiling=1_000_000,
        description="list_files max paths per call (W-100)",
    ),
    EnvVarSpec(
        "AGENTROPIX_RECMD_MAX_ENTRIES",
        default=10000,
        floor=1,
        ceiling=1_000_000,
        description="RECmd max parsed entries per call [W-125]",
    ),
    EnvVarSpec(
        "AGENTROPIX_MFTECMD_MAX_MFT_ENTRIES",
        default=500_000,
        floor=1,
        ceiling=10_000_000,
        description="MFTECmd max MFT entries per call [W-126]",
    ),
    EnvVarSpec(
        "AGENTROPIX_MFTECMD_MAX_JOURNAL_ENTRIES",
        default=50_000,
        floor=1,
        ceiling=10_000_000,
        description="MFTECmd max $J journal entries per call [W-126]",
    ),
    EnvVarSpec(
        "AGENTROPIX_LECMD_MAX_ENTRIES",
        default=5000,
        floor=1,
        ceiling=1_000_000,
        description="LECmd max .lnk entries per call [W-127]",
    ),
    EnvVarSpec(
        "AGENTROPIX_STRINGS_MIN_LENGTH",
        default=4,
        floor=1,
        ceiling=1024,
        description="GNU strings min printable length",
    ),
    EnvVarSpec(
        "AGENTROPIX_EXTRACT_MAX_BYTES",
        default=500 * 1024 * 1024,
        floor=1024,
        ceiling=16 * 1024 * 1024 * 1024,
        description="ifind+icat per-file truncation cap (bytes)",
    ),
    EnvVarSpec(
        "AGENTROPIX_EXTRACT_CONCURRENCY",
        default=4,
        floor=1,
        ceiling=16,
        description="extract_files concurrent invocation cap",
    ),
    EnvVarSpec(
        "AGENTROPIX_FLS_MAX_DEPTH",
        default=10,
        floor=1,
        ceiling=20,
        description="filesystem agent fls recursion depth",
    ),
    EnvVarSpec(
        "AGENTROPIX_HASH_MAX_BYTES",
        default=0,
        description="courtroom hash cap (0 = no cap)",
    ),
    # ----------------------------------------------------------------- #
    # Wrappers — tool-binary overrides                                   #
    # ----------------------------------------------------------------- #
    EnvVarSpec(
        "AGENTROPIX_HASHDEEP_TOOL",
        default="hashdeep",
        description="hashdeep binary name",
    ),
    EnvVarSpec(
        "AGENTROPIX_HASHDEEP_ALGOS",
        default="sha256,md5",
        description="hashdeep algorithms (comma-separated)",
    ),
    EnvVarSpec(
        "AGENTROPIX_EXIFTOOL_TOOL",
        default="exiftool",
        description="exiftool binary name",
    ),
    EnvVarSpec(
        "AGENTROPIX_AMCACHE_TOOL",
        default="amcache.py",
        description="amcache parser binary name",
    ),
    EnvVarSpec(
        "AGENTROPIX_EVTX_TOOL",
        default="evtx_dump.py",
        description="evtx parser binary name (Rust evtx_dump preferred when on PATH; W-136)",
    ),
    EnvVarSpec(
        "AGENTROPIX_EVTX_WORKERS",
        default=6,
        floor=1,
        ceiling=12,
        description="evtx_dump --threads cap and per-channel concurrency limit (W-136)",
    ),
    EnvVarSpec(
        "AGENTROPIX_EVTX_FORCE_JSONL_BYTES",
        default=50 * 1024 * 1024,
        floor=1024 * 1024,
        ceiling=2 * 1024 * 1024 * 1024,
        description="byte threshold above which the wrapper forces -o jsonl (W-136 §3 row 2)",
    ),
    EnvVarSpec(
        "AGENTROPIX_VERIFY_TOOL_PINS",
        default="warn",
        description="tool-pin trust mode: off|warn|strict (W-136 §4.1)",
    ),
    EnvVarSpec(
        "AGENTROPIX_FLS_TOOL",
        default="fls",
        description="TSK fls binary name",
    ),
    EnvVarSpec(
        "AGENTROPIX_FOREMOST_TOOL",
        default="foremost",
        description="foremost binary name",
    ),
    EnvVarSpec(
        "AGENTROPIX_ICAT_TOOL",
        default="icat",
        description="TSK icat binary name",
    ),
    EnvVarSpec(
        "AGENTROPIX_IFIND_TOOL",
        default="ifind",
        description="TSK ifind binary name",
    ),
    EnvVarSpec(
        "AGENTROPIX_PREFETCH_TOOL",
        default="prefetch",
        description="prefetch parser binary name",
    ),
    EnvVarSpec(
        "AGENTROPIX_SHIMCACHE_TOOL",
        default="shimcache.py",
        description="shimcache parser binary name",
    ),
    EnvVarSpec(
        "AGENTROPIX_STRINGS_TOOL",
        default="strings",
        description="GNU strings binary name",
    ),
    EnvVarSpec(
        "AGENTROPIX_YARA_TOOL",
        default="yara",
        description="yara binary name",
    ),
    EnvVarSpec(
        "AGENTROPIX_BE_TOOL",
        default="bulk_extractor",
        description="bulk_extractor binary name",
    ),
    EnvVarSpec(
        "AGENTROPIX_EWFMOUNT_TOOL",
        default="ewfmount",
        description="ewfmount binary name",
    ),
    EnvVarSpec(
        "AGENTROPIX_FUSERMOUNT_TOOL",
        default="fusermount",
        description="fusermount binary name",
    ),
    EnvVarSpec(
        "AGENTROPIX_EWFMOUNT_LAZY_UMOUNT",
        default="true",
        description="fusermount -uz vs -u (lazy unmount)",
    ),
    EnvVarSpec(
        "AGENTROPIX_EWF_TMPDIR",
        default="",
        description="ewfmount tmpdir override (empty = system default)",
    ),
    EnvVarSpec(
        "AGENTROPIX_RECMD_DLL",
        default="/opt/ezt/net9/RECmd/RECmd.dll",
        description="RECmd DLL path override [W-125]",
    ),
    EnvVarSpec(
        "AGENTROPIX_MFTECMD_DLL",
        default="/opt/ezt/net9/MFTECmd/MFTECmd.dll",
        description="MFTECmd DLL path override [W-126]",
    ),
    EnvVarSpec(
        "AGENTROPIX_LECMD_DLL",
        default="/opt/ezt/net9/LECmd/LECmd.dll",
        description="LECmd DLL path override [W-127]",
    ),
    EnvVarSpec(
        "AGENTROPIX_RECMD_BATCH_DIR",
        default="/opt/ezt/net9/RECmd/BatchExamples",
        description="RECmd batch-file directory override [W-125]",
    ),
    EnvVarSpec(
        "AGENTROPIX_RECMD_BATCH",
        default="Kroll_Batch.reb",
        description="RECmd default batch file (in AGENTROPIX_RECMD_BATCH_DIR) [W-125]",
    ),
    EnvVarSpec(
        "AGENTROPIX_DOTNET_TOOL",
        default="dotnet",
        description="dotnet runtime binary name (used by EZ Tools) [W-125/W-126/W-127]",
    ),
    # ----------------------------------------------------------------- #
    # Subprocess host                                                    #
    # ----------------------------------------------------------------- #
    EnvVarSpec(
        "AGENTROPIX_MEM_LIMIT_MB",
        default=4096,
        description="per-subprocess RSS limit (MB; default 4096 since W-141; set to 0 to disable)",
    ),
    EnvVarSpec(
        "AGENTROPIX_MAX_RETRIES",
        default=2,
        description="subprocess retry count on transient failure",
    ),
    EnvVarSpec(
        "AGENTROPIX_MIN_DISK_MB",
        default=500,
        description="plaso pre-flight free-disk floor (MB)",
    ),
    # ----------------------------------------------------------------- #
    # Plaso / parser selection (string-set knobs)                        #
    # ----------------------------------------------------------------- #
    EnvVarSpec(
        "AGENTROPIX_PLASO_PARSERS",
        default="winevtx,mft",
        description="plaso parsers when not overridden by call",
    ),
    EnvVarSpec(
        "AGENTROPIX_PLASO_EXCLUDE_FAMILIES",
        default="",
        description="plaso parser families to skip up-front",
    ),
    EnvVarSpec(
        "AGENTROPIX_TIMELINE_PARSERS",
        default="(see agents/timeline.py default set)",
        description="timeline-agent parser allowlist",
    ),
    EnvVarSpec(
        "AGENTROPIX_TIMELINE_LOLBINS",
        default="(default LOLBin set)",
        description="timeline-agent LOLBin token list",
    ),
    EnvVarSpec(
        "AGENTROPIX_TIMELINE_LOLBIN_CONFIDENCE",
        default=0.7,
        floor=0.0,
        ceiling=1.0,
        description="timeline LOLBin finding confidence",
    ),
    EnvVarSpec(
        "AGENTROPIX_TIMELINE_DEDUP",
        default=1,
        floor=0,
        ceiling=1,
        description="timeline dedup enable (1) / disable (0)",
    ),
    EnvVarSpec(
        "AGENTROPIX_TIMELINE_DEDUP_MSG_CHARS",
        default=80,
        floor=20,
        ceiling=500,
        description="timeline dedup message-prefix window (chars)",
    ),
    EnvVarSpec(
        "AGENTROPIX_TIMELINE_MAX_EVENTS",
        default=5000,
        floor=1,
        ceiling=100_000,
        description="timeline-agent event cap",
    ),
    # ----------------------------------------------------------------- #
    # Memory agent                                                       #
    # ----------------------------------------------------------------- #
    EnvVarSpec(
        "AGENTROPIX_MEMORY_KERNEL_PPIDS",
        default="(default kernel-PPID set)",
        description="memory-agent kernel-PPID allowlist (orphan classifier)",
    ),
    EnvVarSpec(
        "AGENTROPIX_MEMORY_SUSPICIOUS_PROCS",
        default="(default suspicious-proc set)",
        description="memory-agent suspicious process allowlist",
    ),
    EnvVarSpec(
        "AGENTROPIX_MEMORY_SUSPICIOUS_CONFIDENCE",
        default=0.7,
        floor=0.0,
        ceiling=1.0,
        description="memory suspicious-proc finding confidence",
    ),
    EnvVarSpec(
        "AGENTROPIX_MEMORY_ORPHAN_CONFIDENCE",
        default=0.6,
        floor=0.0,
        ceiling=1.0,
        description="memory orphan-proc finding confidence",
    ),
    EnvVarSpec(
        "AGENTROPIX_SUSPICIOUS_PROCS_FILE",
        default="",
        description="suspicious-proc rules file path (overrides inline list)",
    ),
    EnvVarSpec(
        "AGENTROPIX_SUSPICIOUS_FILES_FILE",
        default="",
        description="suspicious-files rules file path (overrides inline list)",
    ),
    # ----------------------------------------------------------------- #
    # Filesystem agent                                                   #
    # ----------------------------------------------------------------- #
    EnvVarSpec(
        "AGENTROPIX_FS_DELETED_CONFIDENCE",
        default=0.55,
        floor=0.0,
        ceiling=1.0,
        description="fs deleted-file finding confidence",
    ),
    EnvVarSpec(
        "AGENTROPIX_FS_SUSPICIOUS_CONFIDENCE",
        default=0.7,
        floor=0.0,
        ceiling=1.0,
        description="fs suspicious-file finding confidence",
    ),
    EnvVarSpec(
        "AGENTROPIX_FS_SUSPICIOUS_FILENAMES",
        default="(default suspicious-filename set)",
        description="fs suspicious-filename allowlist",
    ),
    EnvVarSpec(
        "AGENTROPIX_FS_EMIT_DELETED_ALL",
        default=0,
        description="fs emit deleted-all flag (0 = sample only)",
    ),
    # ----------------------------------------------------------------- #
    # Artifact agent                                                     #
    # ----------------------------------------------------------------- #
    EnvVarSpec(
        "AGENTROPIX_ARTIFACT_EXTRACT",
        default=1,
        description="artifact-agent extract-from-image enable",
    ),
    EnvVarSpec(
        "AGENTROPIX_ARTIFACT_TASKS_ENABLED",
        default=1,
        description="artifact-agent scheduled-tasks scan enable",
    ),
    EnvVarSpec(
        "AGENTROPIX_ARTIFACT_FORMATS",
        default="(default extract format list)",
        description="artifact-agent extract format allowlist",
    ),
    EnvVarSpec(
        "AGENTROPIX_ARTIFACT_COC_CONFIDENCE",
        default=0.95,
        floor=0.0,
        ceiling=1.0,
        description="artifact chain-of-custody finding confidence",
    ),
    EnvVarSpec(
        "AGENTROPIX_ARTIFACT_SUSPICIOUS_CONFIDENCE",
        default=0.7,
        floor=0.0,
        ceiling=1.0,
        description="artifact suspicious-task finding confidence",
    ),
    EnvVarSpec(
        "AGENTROPIX_ARTIFACT_MAX_ENTRIES",
        default=500,
        floor=1,
        ceiling=10000,
        description="artifact-agent max entries returned",
    ),
    EnvVarSpec(
        "AGENTROPIX_ARTIFACT_MAX_TASKS",
        default=500,
        floor=1,
        ceiling=10000,
        description="artifact-agent max scheduled tasks returned",
    ),
    # ----------------------------------------------------------------- #
    # Hunt agent                                                         #
    # ----------------------------------------------------------------- #
    EnvVarSpec(
        "AGENTROPIX_HUNT_CONFIDENCE_BONUS",
        default=0.1,
        floor=0.0,
        ceiling=1.0,
        description="hunt-agent corroboration confidence bonus",
    ),
    EnvVarSpec(
        "AGENTROPIX_HUNT_CONFIDENCE_CAP",
        default=0.95,
        floor=0.0,
        ceiling=1.0,
        description="hunt-agent confidence ceiling",
    ),
    # ----------------------------------------------------------------- #
    # Trinity / Critic                                                   #
    # ----------------------------------------------------------------- #
    EnvVarSpec(
        "AGENTROPIX_CRITIC_HALT_THRESHOLD",
        default=0.85,
        floor=0.0,
        ceiling=1.0,
        description="critic halt threshold",
    ),
    EnvVarSpec(
        "AGENTROPIX_CRITIC_MIN_ITERATIONS",
        default=2,
        floor=1,
        ceiling=10,
        description="critic min iteration floor",
    ),
    EnvVarSpec(
        "AGENTROPIX_TRINITY_FEEDBACK",
        default=1,
        description="architect feedback-driven agent dropping (1=on, 0=off)",
    ),
    # ----------------------------------------------------------------- #
    # Blackboard / shared agent infra                                    #
    # ----------------------------------------------------------------- #
    EnvVarSpec(
        "AGENTROPIX_AGENT_FINDING_CAP",
        default=500,
        floor=10,
        ceiling=10000,
        description="per-agent finding cap (lowest-confidence dropped)",
    ),
    EnvVarSpec(
        "AGENTROPIX_TOKEN_MIN_LENGTH",
        default=3,
        floor=1,
        ceiling=10,
        description="blackboard token min length",
    ),
    EnvVarSpec(
        "AGENTROPIX_TOKEN_ALLOWLIST",
        default="(default short-token allowlist)",
        description="blackboard short-token allowlist",
    ),
    EnvVarSpec(
        "AGENTROPIX_DISK_SUFFIXES",
        default="(default disk-image suffix set)",
        description="archive picker disk-image suffix set",
    ),
    EnvVarSpec(
        "AGENTROPIX_MEMORY_SUFFIXES",
        default="(default memory-dump suffix set)",
        description="archive picker memory-dump suffix set",
    ),
    # ----------------------------------------------------------------- #
    # Volatility netscan                                                 #
    # ----------------------------------------------------------------- #
    EnvVarSpec(
        "AGENTROPIX_VOL_USE_NETSTAT",
        default=0,
        description="vol3 netstat opt-in (0=netscan, 1=netstat)",
    ),
    EnvVarSpec(
        "AGENTROPIX_VOL_TCPIP_SYMBOLS_OK",
        default=0,
        description="vol3 netstat tcpip-symbols sentinel",
    ),
    # ----------------------------------------------------------------- #
    # Hippocampus / memory bridge                                        #
    # ----------------------------------------------------------------- #
    EnvVarSpec(
        "AGENTROPIX_HIPPOCAMPUS_ENABLED",
        default=0,
        description="hippocampus retrieval bridge (0=off, 1=on)",
    ),
    EnvVarSpec(
        "AGENTROPIX_HIPPOCAMPUS_TOP_K",
        default=3,
        floor=1,
        ceiling=50,
        description="hippocampus top-k retrieval",
    ),
    # ----------------------------------------------------------------- #
    # Courtroom / chain-of-custody                                       #
    # ----------------------------------------------------------------- #
    EnvVarSpec(
        "AGENTROPIX_EVIDENCE_SHA",
        default="",
        description="operator-supplied evidence SHA-256 override (legacy)",
    ),
    # ----------------------------------------------------------------- #
    # Telegram delivery (secrets)                                        #
    # ----------------------------------------------------------------- #
    EnvVarSpec(
        "AGENTROPIX_TELEGRAM_TOKEN_FILE",
        default="",
        description="path to file holding Telegram bot token (preferred)",
    ),
    EnvVarSpec(
        "AGENTROPIX_TELEGRAM_TOKEN",
        default="",
        description="Telegram bot token (env var; secrets-handled)",
    ),
    EnvVarSpec(
        "AGENTROPIX_TELEGRAM_BOT_TOKEN",
        default="",
        description="legacy .env Telegram bot token key",
    ),
)

_SECRET_NAMES = frozenset(
    {
        "AGENTROPIX_MCP_AUTH_TOKEN",
        "AGENTROPIX_TELEGRAM_TOKEN",
        "AGENTROPIX_TELEGRAM_BOT_TOKEN",
        # The token *file* path is fine to log — operators want to verify it.
    }
)


def _format_value(spec: EnvVarSpec, value: object) -> str:
    """Render a value for the banner — masking secrets."""
    if spec.name in _SECRET_NAMES and value:
        return "***SET (masked)***"
    return repr(value)


def _format_range(spec: EnvVarSpec) -> str:
    if spec.floor is None and spec.ceiling is None:
        return "no range guard"
    floor_s = "-inf" if spec.floor is None else str(spec.floor)
    ceiling_s = "+inf" if spec.ceiling is None else str(spec.ceiling)
    return f"range {floor_s}-{ceiling_s}"


def build_active_configuration() -> dict[str, dict[str, object]]:
    """Return the active env-var configuration as a structured dict.

    Keys: env-var name. Values: ``{value, default, floor, ceiling,
    description, override}`` where ``override`` is ``True`` iff the var
    is currently set in the process environment.
    """
    out: dict[str, dict[str, object]] = {}
    for spec in _KNOWN_ENV_VARS:
        raw = os.environ.get(spec.name)
        override = raw is not None and raw != ""
        value: object = raw if override else spec.default
        out[spec.name] = {
            "value": value,
            "default": spec.default,
            "floor": spec.floor,
            "ceiling": spec.ceiling,
            "description": spec.description,
            "override": override,
        }
    return out


def _resolve_thymus_prefixes() -> list[str]:
    """Materialize the Thymus allowed-prefix list (defaults + env additions).

    Imported lazily so this module stays importable in unit tests that
    don't need the policy module's side effects.
    """
    from agentropix_mcp.thymus_policy import ThymusEvidencePolicy

    policy = ThymusEvidencePolicy(auto_detect=False)
    # ``_allowed_prefixes`` is the canonical list including env additions.
    return list(policy._allowed_prefixes)  # noqa: SLF001 — banner introspection


def format_active_configuration() -> str:
    """Render the banner as a multi-line string (no logging side effects)."""
    cfg = build_active_configuration()
    name_width = max(len(name) for name in cfg)
    lines: list[str] = []
    header = (
        "================ Agentropix-SIFT MCP Server "
        "— Active Configuration ================"
    )
    lines.append(header)
    for name, entry in cfg.items():
        spec = next(s for s in _KNOWN_ENV_VARS if s.name == name)
        formatted = _format_value(spec, entry["value"])
        default = _format_value(spec, spec.default)
        range_s = _format_range(spec)
        marker = "*" if entry["override"] else " "
        lines.append(
            f"{marker} {name:<{name_width}} = {formatted}  "
            f"(default {default}, {range_s})"
            + (f"  -- {spec.description}" if spec.description else "")
        )
    # Thymus allowed prefixes — list them last so operators see the
    # read-zone surface alongside every other knob.
    lines.append("")
    lines.append("Thymus allowed prefixes (READ-ONLY):")
    for prefix in _resolve_thymus_prefixes():
        lines.append(f"  - {prefix}")
    lines.append("=" * len(header))
    lines.append(
        "Tip: override any AGENTROPIX_* var by exporting it before "
        "starting the server. '*' marker = currently overridden."
    )
    return "\n".join(lines)


def log_active_configuration(target_logger: logging.Logger | None = None) -> None:
    """Emit the active env-var configuration as an INFO-level banner.

    ``target_logger`` defaults to the package logger so the banner shows
    up under the same dotted path operators already filter on.
    """
    log = target_logger or logger
    banner = format_active_configuration()
    # Single multi-line INFO record so operators see the whole table in
    # one log entry rather than 70 individual lines.
    log.info("Startup configuration banner:\n%s", banner)
