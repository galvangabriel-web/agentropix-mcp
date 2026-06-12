# Agentropix-SIFT - Tunable Feature Catalog (explanatory)

_Generated 2026-06-10 - 252 env variables, each read from source by an Opus agent._

Each variable: **purpose** (what it controls), **effect** (raising/lowering or on/off + tradeoff), **default**.

## Feature toggles  (16)

### `AGENTROPIX_ARTIFACT_TASKS_ENABLED`
- **Default:** `1 (enabled) — accepts 1/true/yes/on`
- **Purpose:** On/off switch controlling whether the ArtifactAgent is allowed to spawn follow-up tasks at all.
- **Effect:** On (1/true/yes/on) permits automatic task generation = more autonomous/thorough investigation but more downstream load. Off disables it entirely for a more controlled, predictable run. Truthy default means task spawning is ON.

### `AGENTROPIX_EVTX_CACHE_DISABLE`
- **Default:** `0 (cache enabled)`
- **Purpose:** Toggle that turns the EVTX parse cache off entirely (mainly for tests / forcing fresh parses).
- **Effect:** Set to 1/true/yes to disable caching, forcing every call to re-parse (slower, but guarantees fresh output and no stale-cache risk). Any other value (default '0') keeps the cache enabled.

### `AGENTROPIX_EVTX_VERBOSE`
- **Default:** `0 (OFF)`
- **Purpose:** Boolean (0/1) toggle for verbose Windows EventLog (EVTX) emission. When OFF, matching verbose-EID events are collapsed by dedup into a single finding; when ON, the agent emits one finding per matching verbose-EID event up to the verbose cap.
- **Effect:** On (1) maximizes per-event recall/granularity for EVTX (e.g. individual 4624 logons) at the cost of finding-count volume and noise; Off (0, default) preserves dedup-collapse behaviour. Clamped to 0/1.

### `AGENTROPIX_EVTX_VERBOSE_CAP`
- **Default:** `5000 (_VERBOSE_EVTX_CAP_DEFAULT)`
- **Purpose:** Per-host ceiling on the number of verbose EVTX findings emitted when AGENTROPIX_EVTX_VERBOSE=1. Once reached, further matching events are dropped and counted.
- **Effect:** Raising captures more verbose events (better recall) but more findings/memory; lowering caps output sooner (logs 'dropped=N, raise cap to capture more'). Only has effect when verbose mode is on. Clamped floor 100, ceiling 50000.

### `AGENTROPIX_EWFMOUNT_LAZY_UMOUNT`
- **Default:** `true (lazy, -uz)`
- **Purpose:** Whether EWF FUSE unmount uses lazy mode: true selects 'fusermount -uz', false selects 'fusermount -u'.
- **Effect:** On (default): lazy unmount detaches even when a killed BE subprocess still holds file descriptors on the mount, avoiding EBUSY leftover mounts. Off: a strict unmount may fail with EBUSY and leave the mount dangling, but guarantees no access continues post-unmount. Parsed truthy unless value is one of 0/false/no (case-insensitive).

### `AGENTROPIX_EWF_LIFECYCLE_DISABLE`
- **Default:** `"" (unset -> disabled flag off, lifecycle enabled)`
- **Purpose:** Kill-switch that disables the entire EWF mount lifecycle.
- **Effect:** When set truthy, the lifecycle is skipped and a 'disabled' result is returned instead of mounting evidence; off means mounting proceeds normally. Use to prevent any FUSE/mount activity.

### `AGENTROPIX_FLS_RECURSIVE`
- **Default:** `1 (recursive)`
- **Purpose:** Integer-as-boolean toggle (0/1) controlling whether fls walks the image recursively vs. a single level.
- **Effect:** 1 = recursive full-tree walk (complete coverage, slower); 0 = non-recursive single-directory walk (faster, much lower recall). Clamped floor 0, ceiling 1; cast to bool.

### `AGENTROPIX_FS_EMIT_DELETED_ALL`
- **Default:** `0 (deleted-only-if-suspicious)`
- **Purpose:** Integer-as-boolean toggle restoring legacy behavior of emitting a finding for EVERY deleted/unallocated inode, instead of the W-048 default of only deleted entries whose filename also trips the suspicious-name matcher.
- **Effect:** 1 = emit one finding per unallocated inode (maximum recall, but floods output with tens of thousands of benign deleted browser-cache/temp/log inodes → noise); 0 = only deleted+suspicious-name findings (precise, keeps tools like mimikatz surfacing). Clamped floor 0, ceiling 1.

### `AGENTROPIX_HIPPOCAMPUS_ENABLED`
- **Default:** `0 (off)`
- **Purpose:** Opt-in switch that enables the hippocampus memory-retrieval bridge (vector recall of prior context/findings).
- **Effect:** Off by default; only a truthy value enables it. Read as os.environ.get(..., '0').lower(). Turning it on activates cross-run memory recall (more context, extra lookups/latency); off keeps runs stateless.

### `AGENTROPIX_HIPPOCAMPUS_TOP_K`
- **Default:** `3`
- **Purpose:** Number of top memory entries the hippocampus bridge retrieves per query.
- **Effect:** Higher K recalls more prior context (better recall, more tokens/noise, slower); lower K returns only the closest matches. Clamped to [1, 50].

### `AGENTROPIX_IMPACKET_ENABLED`
- **Default:** `unset (treated as off; only '1' enables)`
- **Purpose:** Opt-in master switch (per ADR-014) that authorizes the agent to shell out to impacket secretsdump for credential dumping from staged hives.
- **Effect:** Must equal exactly '1' to enable; any other value (default unset) skips credential extraction with reason 'AGENTROPIX_IMPACKET_ENABLED!=1 (opt-in per ADR-014)'. Off by default for safety — turning it on enables a security-sensitive credential-dump capability.

### `AGENTROPIX_MAIL_MALDOC_CHAIN_DISABLE`
- **Default:** `0 (enabled)`
- **Purpose:** On/off switch (read as int) for the W-226 maldoc phishing-chain: spilling email attachment bytes to a temp dir and running the post-pass maldoc analysis over them.
- **Effect:** Default 0 = chain ENABLED (attachments spilled + analyzed for malicious-document indicators). Set to 1 to DISABLE and restore pre-W-226 behavior (no spill, no maldoc post-pass) — faster and avoids temp-dir writes, but loses attachment-based detection recall. Clamped floor 0, ceiling 1 (any value !=1 keeps it enabled).

### `AGENTROPIX_T1071_SVCHOST_DISABLE`
- **Default:** `off (unset/empty; truthy for '1','true','yes','on')`
- **Purpose:** Hard off-switch that suppresses all findings from the T1071.001 svchost-outbound-HTTP detector.
- **Effect:** On: detector emits nothing (use to silence a detector that is noisy in a known-benign environment — but you then lose all detection of this PlugX C2 shape). Off (default): detector runs normally. Binary kill switch.

### `AGENTROPIX_TIMELINE_DEDUP`
- **Default:** `1 (ON)`
- **Purpose:** Boolean (0/1) enabling message-prefix deduplication of timeline findings (collapses repeated near-identical events).
- **Effect:** On (1, default) reduces duplicate findings — cleaner output, less noise. Off (0) keeps every event, useful for debugging or when callers need raw per-event findings (more volume). Clamped 0/1.

### `AGENTROPIX_TIMELINE_DEDUP_MSG_CHARS`
- **Default:** `80`
- **Purpose:** Number of leading message characters used as the dedup key (also the minimum prefix for winreg/prefetch dedup) when dedup is enabled.
- **Effect:** Larger value compares more of the message → fewer false-merges (events differing only in a deep field stay distinct, higher precision, less collapse). Smaller value collapses more aggressively (fewer findings). Clamped floor 20, ceiling 500.

### `AGENTROPIX_VOL_USE_NETSTAT`
- **Default:** `"0" (off) — netscan is used`
- **Purpose:** W-075 opt-in toggle to allow the windows.netstat plugin (which needs tcpip.sys symbols) instead of the symbol-free netscan pool-scan for network connection enumeration.
- **Effect:** Off (default) = use netscan, which works on any image without pre-fetched symbol packs (robust, no symbol-fetch failures). On (1/true/yes/on) only takes effect if AGENTROPIX_VOL_TCPIP_SYMBOLS_OK is also on; netstat can yield richer/cleaner connection state but silently produces empty output when tcpip symbols are missing. Both gates must be on to switch.

## Performance / Scaling knobs  (125)

### `AGENTROPIX_AGENT_FINDING_CAP`
- **Default:** `500`
- **Purpose:** Maximum number of findings an agent will emit; when exceeded the lowest-confidence entries are dropped to stay under the cap.
- **Effect:** Raising it retains more findings (more complete, larger reports, more triage load); lowering it trims aggressively, potentially discarding genuine low-confidence hits. Clamped to floor 10 (ceiling per docstring). Resolved from _DEFAULT_AGENT_FINDING_CAP.

### `AGENTROPIX_AMCACHE_TIMEOUT`
- **Default:** `60.0`
- **Purpose:** Wall-clock seconds budget for the Amcache.hve parser subprocess; on expiry the process is killed and TimeoutError raised.
- **Effect:** Raise for large hives or a slow (e.g. Wine-hosted) parser; lower to fail fast. Speed-vs-completeness on execution-evidence parsing. Clamped floor 5.0, ceiling 3600.0.

### `AGENTROPIX_ARCHITECT_LLM_CACHE_SIZE`
- **Default:** `256`
- **Purpose:** Max entries in the process-wide bounded LRU cache for the Architect's LLM plan-reorder results, keyed by SHA-256 of the canonical cache key.
- **Effect:** Raising caches more reorder results across triages in the same MCP process (faster, fewer LLM calls/cost) at cost of memory; 0 disables caching entirely. Clamped to floor 0, ceiling 100000.

### `AGENTROPIX_ARCHIVE_MAX_BYTES`
- **Default:** `53687091200 (_DEFAULT_MAX_BYTES = 50 * 1024^3 = 50 GiB)`
- **Purpose:** Archive-bomb cap on total claimed uncompressed bytes summed across all file entries in the pre-flight inventory.
- **Effect:** Raise to allow larger legitimate archives through; lower to refuse extraction sooner (ValueError before any byte is written). Security/disk-exhaustion guard: too high re-opens decompression-bomb risk, too low blocks real evidence. Clamped floor 1024, ceiling 2**62.

### `AGENTROPIX_ARCHIVE_MAX_FILES`
- **Default:** `1000000 (_DEFAULT_MAX_FILES = 1,000,000)`
- **Purpose:** Archive-bomb cap on the number of file (non-folder) entries the archive may contain.
- **Effect:** Raise to permit archives with many members; lower to refuse high-entry-count bombs earlier (ValueError pre-extraction). Guards against inode/filecount exhaustion. Clamped floor 1, ceiling 2**31-1.

### `AGENTROPIX_ARCHIVE_MAX_PER_FILE_BYTES`
- **Default:** `17179869184 (_DEFAULT_MAX_PER_FILE = 16 * 1024^3 = 16 GiB)`
- **Purpose:** Archive-bomb cap on the claimed uncompressed size of any single entry in the inventory.
- **Effect:** Raise to allow individually huge members; lower to reject any single oversized entry before extraction (ValueError). Catches single-file decompression bombs that fit under the aggregate cap. Clamped floor 1024, ceiling 2**62.

### `AGENTROPIX_ARCHIVE_TIMEOUT`
- **Default:** `600.0 (_DEFAULT_TIMEOUT = 600 s / 10 min)`
- **Purpose:** Wall-clock seconds budget applied to BOTH the 7z pre-flight listing and the extraction subprocess; on expiry the engine is killed/reaped and TimeoutError raised.
- **Effect:** Raise for very large/slow archives so legitimate extraction can finish; lower to fail fast on a wedged engine. Speed-vs-completeness: too low aborts valid big jobs, too high lets a hung engine stall the server longer. Clamped floor 30.0, ceiling 86400.0.

### `AGENTROPIX_ARTIFACT_MAX_ENTRIES`
- **Default:** `50`
- **Purpose:** Caps how many registry entries the ArtifactAgent will parse/return per investigation.
- **Effect:** Raising it improves recall (more registry entries surfaced) at the cost of runtime and output volume; lowering it truncates results, faster but may miss evidence. Clamped to [1, 10000].

### `AGENTROPIX_ARTIFACT_MAX_TASKS`
- **Default:** `500`
- **Purpose:** Upper bound on the number of follow-up tasks the ArtifactAgent will spawn/enqueue.
- **Effect:** Raising it lets the agent fan out more deep-dive tasks (broader coverage, more compute/queue load); lowering it constrains blast radius and resource use but may leave leads unexplored. Clamped to [1, 10000]. Only relevant when task spawning is enabled.

### `AGENTROPIX_BE_MAX_FEATURES`
- **Default:** `1000 (floor 1, ceiling 1,000,000)`
- **Purpose:** Cap on the total number of aggregated bulk_extractor feature rows materialised inline in the BulkReport. The budget is split fairly per recorder (max_features // n_recorders), with high-signal recorders (email/url/ip/ccn/etc) read first.
- **Effect:** Raising returns more carved features inline (better recall for analyst review) at the cost of a larger result payload/memory; lowering trims the inline list sooner and sets truncated=True (per_recorder_counts and on-disk recorder_files still hold the full data, so nothing is lost on disk). Clamped to floor=1, ceiling=1_000_000 via get_int.

### `AGENTROPIX_BE_TIMEOUT`
- **Default:** `3600.0 seconds (floor 60, ceiling 86,400)`
- **Purpose:** Wrapper-level subprocess timeout (seconds) for the bulk_extractor scan; on expiry the process is killed and TimeoutError raised.
- **Effect:** Raising lets long scans of large images finish (better recall on big evidence) but a stuck/runaway scan ties up resources longer; lowering kills slow scans sooner (faster failure, but may abort legitimate large-image scans, losing features). Clamped to floor=60.0, ceiling=86_400.0 via get_float.

### `AGENTROPIX_BSTRINGS_DIR_MAX_FILES`
- **Default:** `256`
- **Purpose:** Cap on the number of files processed when bstrings is pointed at a directory.
- **Effect:** Raising scans more files in a directory (broader coverage) at the cost of runtime; lowering bounds the work. Clamped floor 1, ceiling 10000.

### `AGENTROPIX_BSTRINGS_DLL`
- **Default:** `/opt/ezt/net9/bstrings/bstrings.dll (DEFAULT_DLL)`
- **Purpose:** Filesystem path to the bstrings.dll (.NET assembly from the EZ Tools net9 bundle) invoked via dotnet.
- **Effect:** Override when bstrings is installed elsewhere; if the default path is missing the wrapper raises with a hint to install the EZ Tools net9 zip or set this var. No tradeoff — purely locates the binary.

### `AGENTROPIX_BSTRINGS_MAX_HITS`
- **Default:** `10000`
- **Purpose:** Maximum number of string hits returned from a bstrings run.
- **Effect:** Raising returns more extracted strings (recall) but larger results/memory; lowering truncates output sooner. Clamped floor 1, ceiling 1000000.

### `AGENTROPIX_BSTRINGS_MIN_LENGTH`
- **Default:** `4`
- **Purpose:** Minimum string length passed to bstrings (-m N): only strings at least this many chars are extracted. Used when the min_length call argument is None.
- **Effect:** Lowering captures shorter strings (more recall, much more noise); raising filters to longer, often more meaningful strings (higher precision, fewer hits). Clamped floor 1, ceiling 1024.

### `AGENTROPIX_BSTRINGS_TIMEOUT`
- **Default:** `600.0 seconds`
- **Purpose:** Subprocess timeout in seconds for a bstrings invocation (used when the timeout argument is None).
- **Effect:** Raising allows longer scans of large files to complete (avoids TimeoutError) at the cost of a longer-running tool call; lowering fails fast. Clamped floor 5.0, ceiling 3600.0.

### `AGENTROPIX_CAPA_MAX_RESULTS`
- **Default:** `500`
- **Purpose:** Maximum number of capability matches returned from a capa run.
- **Effect:** Raising returns more capa capabilities (fuller picture, larger output); lowering truncates. get_int floor=1, ceiling=50_000.

### `AGENTROPIX_CAPA_TIMEOUT`
- **Default:** `300.0`
- **Purpose:** Subprocess timeout in seconds for the capa analysis run.
- **Effect:** Raising allows capa to finish on large/complex binaries (better recall, longer hold); lowering aborts slow runs sooner. get_float floor=5.0, ceiling=3600.0.

### `AGENTROPIX_CAPA_TOOL`
- **Default:** `DEFAULT_TOOL_NAME ("capa" on PATH)`
- **Purpose:** Path/name of the FLARE capa binary to invoke (override of the default tool name).
- **Effect:** Set to point at a specific capa install if not on PATH. If unresolved/not on PATH the wrapper skips with guidance to pip install flare-capa or set this var.

### `AGENTROPIX_CRITIC_MIN_ITERATIONS`
- **Default:** `2 (_DEFAULT_MIN_ITERATIONS)`
- **Purpose:** Minimum number of Trinity loop iterations the Critic must run before it is allowed to halt — a defence-in-depth floor so a single saturated high-confidence finding can't short-circuit the loop to iteration 1.
- **Effect:** Raise to force more exploration passes regardless of score (better coverage, more cost/time); lower (min 1) to allow earlier halting. Clamped floor 1, ceiling 10.

### `AGENTROPIX_DISC_MAX_EVENTS`
- **Default:** `10000`
- **Purpose:** Caps the number of events the discovery agent will ingest/process. Bounded to [100, 500000].
- **Effect:** Raising it lets the discovery agent consider more events (higher recall / more complete discovery, slower and more memory). Lowering it processes fewer events (faster, may miss findings). Clamped [100, 500000].

### `AGENTROPIX_DISK_UNWRAP_TIMEOUT`
- **Default:** `300.0 (_DEFAULT_TIMEOUT)`
- **Purpose:** Timeout in seconds for unwrapping/converting a disk container (e.g. extracting raw image from a wrapped container).
- **Effect:** Raising allows large containers to fully unwrap (longer hold); lowering aborts slow unwraps. get_float floor=30.0, ceiling=3600.0 (per module docstring).

### `AGENTROPIX_EDITBOX_MAX_RECORDS`
- **Default:** `10000 (_DEFAULT_MAX_RECORDS; floor 1, ceiling 1,000,000)`
- **Purpose:** Cap on returned EditBoxRecord rows (recovered Edit-control widget contents) from the Volatility 2.6 editbox plugin.
- **Effect:** Raising returns more recovered edit-control text (better recall of typed credentials/IM/RDP content) at higher payload cost; lowering truncates sooner (truncated=True when more raw blocks than allowed were seen). Clamped to floor=1 (_MAX_RECORDS_FLOOR), ceiling=1_000_000 (_MAX_RECORDS_CEILING) via get_int.

### `AGENTROPIX_EDITBOX_TIMEOUT_S`
- **Default:** `600.0 seconds (_DEFAULT_TIMEOUT_S; floor 60, ceiling 7200)`
- **Purpose:** Subprocess timeout (seconds) applied to BOTH the Vol2.6 'imageinfo' profile autodetect run and the 'editbox' plugin run; on expiry the whole process group is SIGKILLed (start_new_session) and TimeoutError raised.
- **Effect:** Raising lets imageinfo and the editbox walk finish on large memory dumps (better recall); lowering fails fast on hung Vol2 (which spawns Python2 helper threads) but may abort legitimate long scans. Clamped to floor=60.0 (_TIMEOUT_FLOOR), ceiling=7200.0 (_TIMEOUT_CEILING) via get_float.

### `AGENTROPIX_EMAIL_MATRIX_MAX_MESSAGES`
- **Default:** `5000 (_DEFAULT_MAX_MESSAGES)`
- **Purpose:** Cap on the number of EML/MSG messages processed when building the per-message header matrix (From/Date/SPF/DKIM/DMARC/first-hop, etc.) over a corpus directory. Also part of the LRU cache key.
- **Effect:** Raise to scan more messages from a large corpus (higher recall on auth-failure/header analysis, more CPU/time); lower to bound the scan. Recall-vs-speed tradeoff. Clamped floor 1, ceiling 100,000.

### `AGENTROPIX_EMAIL_MAX_BYTES`
- **Default:** `33554432 bytes (32 MiB)`
- **Purpose:** Maximum size (bytes) of an email/mbox file the header-matrix parser will process; files larger are rejected.
- **Effect:** Raising it permits parsing larger mailboxes (better coverage, more memory/time); lowering it rejects big files early to bound resource use. Clamped to floor 4 KiB (_FLOOR_MAX_BYTES=4*1024) and ceiling 1 GiB (_CEILING_MAX_BYTES=1*1024*1024*1024). Oversize files raise an error citing this var. Default _DEFAULT_MAX_BYTES = 32*1024*1024.

### `AGENTROPIX_EMAIL_MAX_MESSAGES`
- **Default:** `100000`
- **Purpose:** Caps the number of messages walked/parsed across the email-header analysis; once hit, remaining files are skipped.
- **Effect:** Raising it analyzes more messages (better recall on large corpora, slower); lowering it bounds the walk for speed, but remaining files are skipped (a logged truncation). Clamped to floor 1 and ceiling 10,000,000. Default _DEFAULT_MAX_MESSAGES = 100_000.

### `AGENTROPIX_EVTX_CACHE_MAX_BYTES`
- **Default:** `10737418240 bytes (10 GiB)`
- **Purpose:** Size ceiling for the EVTX cache; when exceeded, least-recently-used cache entries are evicted.
- **Effect:** Raise to keep more parsed logs cached (faster re-runs, more disk used); lower to cap disk footprint (more cache misses → slower). Clamped to floor 1 GiB, ceiling 200 GiB.

### `AGENTROPIX_EVTX_FORCE_JSONL_BYTES`
- **Default:** `52428800 bytes (50 MiB; _DEFAULT_FORCE_JSONL_BYTES = 50*1024*1024)`
- **Purpose:** Byte threshold of the EVTX file above which the wrapper forces the Rust evtx_dump '-o jsonl' output mode (streamed, faster on large logs). Only applies when the resolved tool is the Rust binary.
- **Effect:** Lower it to use JSONL streaming for smaller files (faster/lower-memory on big logs but adds overhead for tiny ones); raise it to keep default XML-style parsing for larger files. Clamped floor 1 MiB, ceiling 2 GiB.

### `AGENTROPIX_EVTX_MAX_EVENTS`
- **Default:** `5000`
- **Purpose:** Caps the number of parsed Windows events returned per EVTX parse call.
- **Effect:** Raise to return more events (better recall/completeness, more time and memory/output size); lower to truncate output (faster, but may miss events). Clamped floor 1, ceiling 100000.

### `AGENTROPIX_EVTX_TIMEOUT`
- **Default:** `180.0 seconds`
- **Purpose:** Per-call wall-clock timeout (seconds) for the EVTX parser subprocess. Also clamps any caller-supplied timeout passed via the API.
- **Effect:** Raise to let large logs (e.g. Security.evtx) finish parsing instead of being killed (better recall, longer worst-case wait); lower to fail fast. Clamped floor 5s, ceiling 3600s.

### `AGENTROPIX_EVTX_WORKERS`
- **Default:** `6`
- **Purpose:** Bounded concurrency/thread cap for EVTX parsing — both the Rust binary's '--threads N' and an asyncio semaphore limiting concurrent MCP parse calls. Rust-only.
- **Effect:** Raise for more parallelism/throughput on multi-core hosts (more CPU/memory contention); lower to throttle a burst of MCP calls. Clamped floor 1, ceiling 12.

### `AGENTROPIX_EWFMOUNT_TIMEOUT`
- **Default:** `30.0 seconds (floor 5, ceiling 300)`
- **Purpose:** Timeout (seconds) for the ewfmount FUSE-mount of an EWF/E01 image before scanning.
- **Effect:** Raising allows slow/large multi-segment EWF images more time to mount (avoids spurious mount failures); lowering fails fast if ewfmount hangs but may abort legitimately slow mounts. Clamped to floor=5.0, ceiling=300.0 via get_float.

### `AGENTROPIX_EWFMOUNT_TIMEOUT_S`
- **Default:** `60 seconds`
- **Purpose:** Per-step timeout (seconds) for ewfmount and related mount-lifecycle commands.
- **Effect:** Raising tolerates slow/large E01 mounts; lowering fails stuck mounts faster. Clamped to 5..300s via get_int.

### `AGENTROPIX_EWF_TIMEOUT`
- **Default:** `30.0 seconds`
- **Purpose:** Subprocess timeout (seconds) for the EWF (Expert Witness Format / E01) tool invocation in this wrapper.
- **Effect:** Raising it tolerates slower EWF operations before aborting; lowering it fails fast on hangs. Clamped to [5.0, 3600.0] seconds.

### `AGENTROPIX_EXIFTOOL_MAX_FILES`
- **Default:** `2000`
- **Purpose:** Maximum number of files exiftool will process in one call (used when the max_files argument is None).
- **Effect:** Raising allows metadata extraction across larger file sets (broader coverage) at the cost of runtime; lowering bounds the batch. Clamped floor 1, ceiling 200000.

### `AGENTROPIX_EXIFTOOL_TIMEOUT`
- **Default:** `120.0 seconds`
- **Purpose:** Subprocess timeout in seconds for an exiftool invocation (used when the timeout argument is None).
- **Effect:** Raising lets larger/slower extractions finish instead of timing out; lowering fails fast. Clamped floor 5.0, ceiling 3600.0.

### `AGENTROPIX_EXTRACT_CONCURRENCY`
- **Default:** `4 (clamped to 1-16)`
- **Purpose:** Size of the per-server semaphore bounding concurrent extraction/tool operations.
- **Effect:** Raising increases parallelism/throughput at the cost of CPU/memory/IO pressure; lowering serializes work for stability. Value is clamped to max(1, min(16, int(env))).

### `AGENTROPIX_EXTRACT_MAX_BYTES`
- **Default:** `268435456 bytes (256 MiB)`
- **Purpose:** Maximum number of bytes that may be extracted/read from a single file inside an image via icat before truncation; guards against runaway extraction.
- **Effect:** Raising it allows larger files to be pulled out fully (better evidence completeness) at the cost of memory/disk/time; lowering it truncates sooner, faster and safer against giant files but risks cutting off evidence. Default _DEFAULT_MAX_BYTES = 256*1024*1024.

### `AGENTROPIX_EXTRACT_MAX_DIR_FILES`
- **Default:** `512`
- **Purpose:** Caps how many files an ifind directory-walk extraction will enumerate/extract from a directory.
- **Effect:** Raising it walks more files per directory (better recall, slower, more output); lowering it limits enumeration for speed and bounded blast radius but may skip files. Clamped to [1, 10000].

### `AGENTROPIX_EXTRACT_TIMEOUT`
- **Default:** `60.0 seconds`
- **Purpose:** Subprocess timeout (seconds) for Sleuth Kit extraction tool invocations (icat/ifind/istat).
- **Effect:** Raising it tolerates slow/large extractions before aborting (fewer spurious timeouts on big images, but a hung tool ties up resources longer); lowering it fails fast. Clamped to [5.0, 3600.0] seconds.

### `AGENTROPIX_FLS_MAX_DEPTH`
- **Default:** `5`
- **Purpose:** Maximum directory-recursion depth used when the FilesystemAgent walks a disk image with Sleuth Kit fls.
- **Effect:** Raise to walk deeper directory trees (better coverage of nested paths, slower/larger walk); lower to bound the walk (faster, may miss deeply nested artifacts). Clamped floor 1, ceiling 20.

### `AGENTROPIX_FOREMOST_MAX_ENTRIES`
- **Default:** `5000`
- **Purpose:** Caps the number of carved-file entries foremost returns from a file-carving run (default when caller passes none).
- **Effect:** Raise to surface more carved artifacts (better recall on deleted/embedded files, larger output); lower to cap (faster, may miss carved files). Clamped floor 1, ceiling 1000000.

### `AGENTROPIX_FOREMOST_TIMEOUT`
- **Default:** `300.0 seconds`
- **Purpose:** Wall-clock timeout (seconds) for the foremost carving subprocess (default when caller passes none).
- **Effect:** Raise to let carving of large images finish (better recall, much longer worst case); lower to fail fast. Clamped floor 5s, ceiling 86400s (24h) — note the wide ceiling reflects that full-image carving can be very long-running.

### `AGENTROPIX_FUSERMOUNT_TIMEOUT`
- **Default:** `10.0 seconds (floor 2, ceiling 60)`
- **Purpose:** Timeout (seconds) for the fusermount unmount of the EWF mount (called best-effort from a finally block).
- **Effect:** Raising gives a slow unmount more time to complete cleanly; lowering returns faster but may leave the unmount incomplete (errors are swallowed). Clamped to floor=2.0, ceiling=60.0 via get_float.

### `AGENTROPIX_GPT_TIMEOUT`
- **Default:** `30.0 (_DEFAULT_TIMEOUT)`
- **Purpose:** Wall-clock seconds budget for each sgdisk subprocess (--print and per-partition --info) in the GPT parser. (Note: the separate ewfmount step uses a fixed 30 s, not this var.)
- **Effect:** Raise for slow/large disk images so sgdisk passes complete; lower to fail fast. On timeout _run returns rc=-1 (the call degrades to an error dict rather than raising). Speed-vs-completeness. Clamped floor 5.0, ceiling 300.0.

### `AGENTROPIX_HASHDEEP_MAX_FILES`
- **Default:** `5000`
- **Purpose:** Upper bound on how many files hashdeep will hash in one wrapper call.
- **Effect:** Raise to hash more files per run (better coverage, longer runtime); lower to cap work (faster, may skip files). Clamped floor 1, ceiling 500000.

### `AGENTROPIX_HASHDEEP_TIMEOUT`
- **Default:** `300.0 seconds`
- **Purpose:** Wall-clock timeout (seconds) for the hashdeep subprocess.
- **Effect:** Raise to allow hashing of large file sets to complete (better recall, longer worst-case wait); lower to fail fast. Clamped floor 5s, ceiling 3600s.

### `AGENTROPIX_HASH_MAX_BYTES`
- **Default:** `53687091200 bytes (50 GiB)`
- **Purpose:** Maximum evidence-image size (bytes) the courtroom module will hash inline; above this it skips inline hashing and warns to use AGENTROPIX_EVIDENCE_SHA256 instead.
- **Effect:** Raising it allows inline SHA-256 of larger images (full integrity record but long, I/O-heavy hashing); lowering it skips hashing sooner to avoid expensive reads. Invalid (non-int) values log a warning and fall back to the default. Default _DEFAULT_MAX_HASH_BYTES = 50*1024*1024*1024.

### `AGENTROPIX_IFEO_CORRELATION_WINDOW_SEC`
- **Default:** `300 (5 minutes)`
- **Purpose:** Time budget (seconds) for pairing an IFEO Debugger registry write with a subsequent debugger execution event: an exec is correlated if its timestamp falls in [write_ts, write_ts + window_sec + skew].
- **Effect:** Widening pairs writes with executions further apart (more recall of the write→exec persistence chain, more risk of coincidental pairing/false positives); narrowing demands tighter temporal coupling (higher precision, may miss slow-triggering hijacks). Clamped floor 60, ceiling 3600.

### `AGENTROPIX_IFEO_DEBUGGER_HASH_TIMEOUT_SEC`
- **Default:** `30 seconds`
- **Purpose:** Intended timeout (seconds) for hashing the IFEO debugger binary. Currently inert: the value is threaded through _extract_writes but explicitly discarded (`_ = debugger_hash_to`), kept on the signature as a placeholder for future Authenticode/hash verification work.
- **Effect:** At present changing it has no runtime effect. Once wired, raising would allow hashing larger debugger binaries before timing out; lowering fails the hash faster. Clamped floor 5, ceiling 600.

### `AGENTROPIX_JLECMD_MAX_ENTRIES`
- **Default:** `10000 (10_000)`
- **Purpose:** Caps the number of parsed jump-list entries returned from JLECmd CSV output; when exceeded the result is marked truncated=True. Read via get_int, floor=1, ceiling=1,000,000.
- **Effect:** Raising it returns more jump-list entries (higher recall on heavily-used systems, larger output/memory). Lowering it truncates sooner (faster/leaner but the truncated flag warns that entries were dropped — possible missed artifacts). Clamped [1, 1000000].

### `AGENTROPIX_JLECMD_TIMEOUT`
- **Default:** `120.0 (seconds)`
- **Purpose:** Wall-clock timeout (seconds) for the JLECmd subprocess. Read via get_float, floor=5.0, ceiling=3600.0.
- **Effect:** Raising it tolerates slow/large jump-list sets (fewer timeouts, longer max hang). Lowering it fails fast (may abort large parses). Clamped [5, 3600]s.

### `AGENTROPIX_LECMD_MAX_ENTRIES`
- **Default:** `10000 (floor 1, ceiling 1,000,000)`
- **Purpose:** Cap on parsed LECmdEntry rows (one per .lnk file) returned from an LECmd run.
- **Effect:** Raising returns more .lnk entries inline (better recall when scanning a directory of shortcuts for persistence/stager evidence) at higher payload cost; lowering truncates sooner (truncated=True), risking missed shortcuts. Clamped to floor=1, ceiling=1_000_000 via get_int.

### `AGENTROPIX_LECMD_TIMEOUT`
- **Default:** `120.0 seconds (floor 5, ceiling 3600)`
- **Purpose:** Subprocess timeout (seconds) for the LECmd run; on expiry the process is killed and TimeoutError raised.
- **Effect:** Raising allows large directory scans of .lnk files to finish (better recall); lowering fails fast on a stuck run but may abort legitimate large scans. Clamped to floor=5.0, ceiling=3600.0 via get_float.

### `AGENTROPIX_LIST_FILES_MAX_RESULTS`
- **Default:** `10000 (floor 1, ceiling 1_000_000)`
- **Purpose:** Default and clamp bound for the maximum number of paths the list_files tool returns.
- **Effect:** When no per-call max_results is given this is the default; per-call overrides are clamped to the same floor=1, ceiling=1_000_000. Raising returns more results (completeness, larger payloads/slower); lowering truncates listings.

### `AGENTROPIX_MAIL_MAX_BYTES`
- **Default:** `50000000 (_DEFAULT_MAX_BYTES = 50,000,000 bytes / 50 MB)`
- **Purpose:** Per-file read cap: maximum bytes read from each discovered/carved mail artifact (PST/OST/MSG/EML) before parsing.
- **Effect:** Raise to ingest larger mailbox/message files in full; lower to bound memory/time per file (oversized tails are simply not read, so very large mailboxes may be partially parsed). Recall-vs-memory tradeoff. Clamped floor 4096, ceiling 500,000,000.

### `AGENTROPIX_MAIL_MAX_MESSAGES`
- **Default:** `5000 (_DEFAULT_MAX_MESSAGES)`
- **Purpose:** Cap on the number of parsed messages kept per file before running the T1566 detectors (messages beyond the cap are truncated).
- **Effect:** Raise to analyze more messages from large PST/OST containers (higher recall, more CPU/time); lower to bound detector workload (may miss findings in later messages). Recall-vs-speed tradeoff. Clamped floor 1, ceiling 100,000.

### `AGENTROPIX_MALFIND_DUMP_MAX_BYTES`
- **Default:** `4194304 (4 MiB; _MALFIND_DUMP_BYTES_DEFAULT = 4*1024*1024; floor 1 MiB, ceiling 32 MiB)`
- **Purpose:** Per-VAD byte cap when _dump_vad() dumps a single suspicious VAD region (windows.vadinfo.VadInfo --dump) for hashing/string extraction.
- **Effect:** VADs larger than the cap are dropped entirely (return b"") rather than truncated, so a partial SHA-256 never reaches a Finding (avoids VT-lookup mismatches). Raise to capture larger injected regions (more recall, more disk/runtime/memory); lower to bound resource use (may skip large legitimate-but-suspicious VADs). Clamped to floor 1 MiB, ceiling 32 MiB.

### `AGENTROPIX_MALFIND_DUMP_MAX_PER_HOST`
- **Default:** `100 (_MALFIND_DUMP_MAX_PER_HOST_DEFAULT; floor 10, ceiling 1000)`
- **Purpose:** Cap on the number of successful VAD-dump attempts per host/image when enriching malfind hits with payload (dump/hash/strings) Findings.
- **Effect:** Stops dumping after N attempts to bound disk and runtime on hosts with hundreds of RWX VADs. Hits beyond the cap keep empty payload fields (their original flag Finding is unaffected, so detection is not lost — only the payload enrichment). Raise for fuller payload coverage at cost of time/disk; lower to stay fast. Clamped to floor 10, ceiling 1000.

### `AGENTROPIX_MALFIND_STRING_MIN_LEN`
- **Default:** `4 (_MALFIND_STRING_MIN_LEN_DEFAULT; floor 4, ceiling 32)`
- **Purpose:** Minimum length of printable-ASCII runs extracted from dumped malfind VAD regions (the 'strings' floor for injected-code dumps), read via get_int.
- **Effect:** Lower => more, shorter strings surfaced (more noise: short alphabet fragments crowd out URL/path/API hits, lower precision). Higher => only longer, more meaningful strings (higher precision, may miss short IOCs). Clamped to floor 4, ceiling 32.

### `AGENTROPIX_MAX_AUTO_PREFIXES`
- **Default:** `50`
- **Purpose:** Caps how many path prefixes the Thymus policy may auto-detect/allow (e.g. evidence-image parent dirs) to prevent prefix explosion.
- **Effect:** Raising lets more directories be auto-allowed (more convenience, weaker containment/larger attack surface); lowering tightens the allowlist. Can be overridden per-instance via constructor arg.

### `AGENTROPIX_MAX_RETRIES`
- **Default:** `2`
- **Purpose:** Default maximum number of retries for retryable subprocess invocations when a caller doesn't pass an explicit max_retries.
- **Effect:** Raising it improves resilience to transient failures (more robustness, longer worst-case latency on persistent failures); lowering it fails faster. Invalid values warn and fall back to 2. Parsed from env string '2'.

### `AGENTROPIX_MCP_RESULT_MAX_BYTES`
- **Default:** `900000 bytes (900 KB)`
- **Purpose:** Serialized-byte ceiling (RESULT_MAX_BYTES) applied to any MCP tool result before it is returned to the client. Default 900KB leaves headroom under the hard 1MB Claude Desktop cap.
- **Effect:** Raising lets larger result payloads through (fewer truncations, more data per call) but risks exceeding client message caps; lowering forces tighter truncation. The env value is itself clamped in code to [50000, 5000000] bytes. Override on clients without the 1MB cap.

### `AGENTROPIX_MEMDUMP_GREP_MAX_HITS`
- **Default:** `200 (_MEMDUMP_GREP_MAX_HITS_DEFAULT; floor 10, ceiling 10000)`
- **Purpose:** Cap on the number of pattern hits returned by the memdump-grep path (regex/string search over a dumped process image).
- **Effect:** Bounds the size of the returned hit list. Internally strings_max = max(ceiling, max_hits*50) so the underlying strings pass stays wider than the cap. Raise to see more matches on noisy patterns (more recall, larger payload); lower to keep reports compact. Clamped to floor 10, ceiling 10000.

### `AGENTROPIX_MEMDUMP_MAX_BYTES`
- **Default:** `4294967296 (4 GiB; _MEMDUMP_MAX_BYTES_DEFAULT = 4*1024*1024*1024; floor 64 MiB, ceiling 16 GiB)`
- **Purpose:** Maximum allowed size of a full process memory dump (vol3 memmap/pslist dump) before the memdump and memdump-grep paths refuse it; read via get_int.
- **Effect:** Dumps exceeding the cap are skipped with dump_size_bytes=0 + skipped_reason (never raises). Raise to allow dumping very large processes (Outlook with big mailboxes, Chrome renderers, MsMpEng, injected svchost commonly exceed 1 GiB) at cost of disk/time; lower to bound resources (may skip large but relevant processes => recall loss). Clamped to floor 64 MiB, ceiling 16 GiB.

### `AGENTROPIX_MEM_LIMIT_MB`
- **Default:** `4096 (MB); env unset → _DEFAULT_MEM_LIMIT_MB=4096`
- **Purpose:** Memory cap (MB, RLIMIT-style) applied to spawned subprocesses; env override wins over image-size-derived scaling. Special value 0 disables the guard entirely.
- **Effect:** Raising it lets memory-heavy tools (e.g. plaso/volatility) run without OOM-kill (more capacity, less host protection); lowering it constrains them; 0 removes the guard. Image-aware fallback computes max(_DEFAULT_MEM_LIMIT_MB=4096, size_GB*730); when unset/invalid/no path it uses the static default. Default 4096 MB.

### `AGENTROPIX_MEM_MAIL_CARVE_BUDGET_MB`
- **Default:** `4096 (_DEFAULT_BUDGET_MB = 4096 MB / 4 GB)`
- **Purpose:** Size gate (in MB) for memory-image email carving: images larger than this are skipped entirely (return []) without running bulk_extractor or the sliding-window RFC822 scan. Also pre-checked in mail.py to emit an actionable Finding instead of a silent skip.
- **Effect:** Raise to allow carving from larger memory dumps (e.g. the 17 GB base-mail-memory image that exceeds the default and yields 0 T1566 findings); lower to protect against long/expensive scans. Recall-vs-runtime tradeoff — the key knob to unblock detection on big mail hosts. Clamped floor 64, ceiling 32768.

### `AGENTROPIX_MEM_MAIL_MIN_HEADER_COUNT`
- **Default:** `2 (_DEFAULT_MIN_HEADER_COUNT)`
- **Purpose:** Minimum number of non-empty RFC822 headers a carved candidate block must have (in addition to non-empty From and Subject) to be accepted and written as an .eml.
- **Effect:** Raise to demand richer headers, rejecting thin fragments (higher precision, fewer false carves, lower recall); lower toward 1 to accept sparser candidates (higher recall, more noise/false positives). Precision/recall tradeoff. Clamped floor 1, ceiling 10.

### `AGENTROPIX_MFTECMD_MAX_JOURNAL_ENTRIES`
- **Default:** `50000 (floor 1, ceiling 5,000,000)`
- **Purpose:** Cap on parsed MFTECmdEntry rows when the artifact is a USN journal ($J / $UsnJrnl). Selected over the MFT cap when artifact_type == 'journal'.
- **Effect:** Raising returns more journal change-log entries (better activity-timeline recall on busy volumes) at higher memory/payload cost and slower parse; lowering truncates the journal sooner (truncated=True), risking missed file-activity events. Clamped to floor=1, ceiling=5_000_000 via get_int.

### `AGENTROPIX_MFTECMD_MAX_MFT_ENTRIES`
- **Default:** `100000 (floor 1, ceiling 10,000,000)`
- **Purpose:** Cap on parsed MFTECmdEntry rows for non-journal artifacts (the $MFT and any non-'journal' type).
- **Effect:** Raising captures more MFT file records inline (better filesystem-metadata recall on large volumes) at higher memory/payload cost; lowering truncates sooner (truncated=True), risking missed files. Clamped to floor=1, ceiling=10_000_000 via get_int.

### `AGENTROPIX_MFTECMD_TIMEOUT`
- **Default:** `180.0 seconds (floor 5, ceiling 3600)`
- **Purpose:** Subprocess timeout (seconds) for the MFTECmd run; on expiry the process is killed and TimeoutError raised.
- **Effect:** Raising allows large $MFT/$J parses to finish (better recall on big volumes); lowering fails fast on a stuck run but may abort legitimate large parses. Clamped to floor=5.0, ceiling=3600.0 via get_float.

### `AGENTROPIX_MIN_DISK_MB`
- **Default:** `500 (MB)`
- **Purpose:** Minimum free disk space (in MB) required on /tmp before plaso (log2timeline) is allowed to run, since plaso stages its storage there and needs ~2x image size.
- **Effect:** Raising it makes the pre-flight check stricter and aborts earlier with a RuntimeError on tight hosts (safer against disk-exhaustion crashes mid-run, but more failed runs). Lowering it permits runs on hosts with less free space at the risk of plaso failing partway through and corrupting/aborting the timeline. Pure gate; no recall/precision effect on results.

### `AGENTROPIX_MMLS_TIMEOUT`
- **Default:** `120.0`
- **Purpose:** Wall-clock seconds budget for the Sleuth Kit mmls partition-enumeration subprocess; on expiry mmls is killed and TimeoutError raised.
- **Effect:** Raise for slow/large or remote-backed images; lower to fail fast. Speed-vs-completeness on partition discovery. Clamped floor 5.0, ceiling 3600.0.

### `AGENTROPIX_NTFS_MOUNT_TIMEOUT_S`
- **Default:** `60 seconds`
- **Purpose:** Per-step timeout (seconds) for the ntfs-3g mount of the partition.
- **Effect:** Raising tolerates slow NTFS mounts; lowering aborts hung ntfs-3g sooner. Clamped to 5..300s.

### `AGENTROPIX_NULL_SESSION_BASELINE_REFRESH_CONCURRENCY`
- **Default:** `2`
- **Purpose:** Maximum number of concurrent baseline-refresh operations, enforced via a per-cap asyncio.Semaphore cache.
- **Effect:** Higher concurrency refreshes baselines faster (more CPU/IO pressure, possible contention); lower serializes refreshes (gentler on the host, slower). Clamped to [1, 8].

### `AGENTROPIX_NULL_SESSION_BASELINE_TTL_HOURS`
- **Default:** `168`
- **Purpose:** Age limit (hours) after which a cached baseline is considered TTL-stale and must be refreshed/recomputed rather than reused.
- **Effect:** Raising it reuses baselines longer (faster, less recompute, but risks comparing against drifted/stale normal); lowering it forces fresher baselines (more accurate, more compute). Clamped to [24, 720] (1-30 days). Default 168 = 7 days.

### `AGENTROPIX_NULL_SESSION_MAX_EVENTS`
- **Default:** `200000`
- **Purpose:** Cap on the number of Security 4624 events pulled from the EVTX corpus for a single analysis run (passed to get_evtx max_events).
- **Effect:** Raising it analyzes more history (better statistical baseline, slower, more memory); lowering it speeds runs but may truncate events and weaken the baseline / miss late activity. Clamped to [1000, 1000000].

### `AGENTROPIX_NULL_SESSION_TOP_K_IPS`
- **Default:** `5`
- **Purpose:** How many of the highest-volume source IPs are retained/reported as top enumeration candidates.
- **Effect:** Higher K surfaces more suspect IPs in findings (more coverage, more output to triage); lower K focuses on the worst offenders only. Clamped to [1, 50].

### `AGENTROPIX_NULL_SESSION_WINDOW_HOURS`
- **Default:** `1`
- **Purpose:** Width (in hours) of the time bucket over which 4624 events are aggregated per IP before comparison to the baseline.
- **Effect:** Larger windows smooth bursts and aggregate counts (may dilute short sharp spikes, reducing detection of fast bursts); smaller windows are more sensitive to bursts. Clamped to [1, 24].

### `AGENTROPIX_PDF_EXTRACT_TIMEOUT`
- **Default:** `180.0 seconds (_DEFAULT_TIMEOUT)`
- **Purpose:** Per-extraction subprocess timeout (seconds) for the pdftotext/pdfinfo run.
- **Effect:** Raising allows large/slow PDFs to finish (better recall) at cost of slower worst-case and more hang exposure; lowering fails slow PDFs faster. Clamped to floor 5.0s, ceiling 3600.0s.

### `AGENTROPIX_PDF_MAX_BYTES`
- **Default:** `209715200 bytes = 200 MiB (_DEFAULT_MAX_BYTES = 200 * 1024 * 1024)`
- **Purpose:** Hard cap on input PDF file size accepted for extraction.
- **Effect:** Raising permits larger evidence PDFs (better coverage) but increases memory/time and DoS exposure; lowering rejects big files early. Files over the cap are refused.

### `AGENTROPIX_PDF_MAX_CHARS`
- **Default:** `200000 characters (_DEFAULT_MAX_CHARS = 200_000)`
- **Purpose:** Cap on number of characters of extracted text returned.
- **Effect:** Raising returns more text (less truncation, better recall) but larger payloads/slower; lowering truncates sooner. Floor 100.

### `AGENTROPIX_PDF_MAX_PAGES`
- **Default:** `1000 pages (_DEFAULT_MAX_PAGES)`
- **Purpose:** Cap on number of PDF pages processed for extraction.
- **Effect:** Raising processes more pages of large docs (better recall) at cost of speed; lowering bounds work on huge PDFs.

### `AGENTROPIX_PLASO_MAX_EVENTS`
- **Default:** `500`
- **Purpose:** Caps the number of timeline events returned/processed from the plaso output (read via get_int with floor=1, ceiling=100000).
- **Effect:** Raising it returns more events (higher recall / more complete timeline) at the cost of more memory, larger payloads, and slower downstream processing. Lowering it truncates the timeline (faster, smaller, but may drop forensically relevant events). Hard-capped at 100000.

### `AGENTROPIX_PLASO_PER_PARSER_BUDGET`
- **Default:** `150 (_DEFAULT_PER_PARSER_BUDGET)`
- **Purpose:** Per-parser event budget — the max number of events retained from any single parser when assembling the bounded result (floor 1; applied across parsers consistently).
- **Effect:** Raising it keeps more events from each individual parser (better recall per artifact source, larger output, slower) — prevents one noisy parser from being starved. Lowering it tightens per-parser caps so a single chatty parser cannot dominate the budget (more balanced, smaller, but may drop relevant events from high-volume parsers).

### `AGENTROPIX_PLASO_PRIORITY_BUDGET`
- **Default:** `200 (_DEFAULT_PRIORITY_BUDGET)`
- **Purpose:** Total event budget for the priority/high-value events deque (floor 0) — the overall cap on prioritized events surfaced from the timeline.
- **Effect:** Raising it surfaces more priority events overall (higher recall, larger output, more downstream cost). Lowering it (down to floor 0) trims the prioritized set aggressively (faster, leaner, risk of dropping high-value forensic events). Works together with the per-parser budget to bound total output.

### `AGENTROPIX_PLASO_TIMEOUT`
- **Default:** `unset → falls through to auto-scale: min(TIMEOUT_CAP, max(1800, image_GB*475)); env value is floored at 30s and an invalid value is ignored with a warning`
- **Purpose:** Explicit wall-clock timeout (seconds) for the log2timeline subprocess, overriding the size-based auto-scale formula. Resolution order: explicit kwarg > this env var > auto-scale.
- **Effect:** Setting a higher value gives large images more time to finish (fewer WRAPPER_TIMEOUT failures on big E01s) at the cost of longer worst-case hangs. Setting it lower fails fast but may truncate big-image processing. Floor is 30s.

### `AGENTROPIX_PLASO_TIMEOUT_CAP`
- **Default:** `7200 (seconds; also the hard ceiling)`
- **Purpose:** Upper ceiling applied to the auto-scaled plaso timeout (only used when AGENTROPIX_PLASO_TIMEOUT is not set). Read via get_int with floor=30, ceiling=7200.
- **Effect:** Raising it (up to the 7200s hard cap) lets the auto-scale formula grant very large images more runtime before timing out (fewer timeouts on huge disks, longer max hang). Lowering it bounds the worst-case auto-scaled timeout more tightly (fail-fast, but big images may not finish). Floor 30s, ceiling 7200s.

### `AGENTROPIX_PLASO_WORKERS`
- **Default:** `6 (_DEFAULT_PLASO_WORKERS; raised from 4 to 6 per W-136)`
- **Purpose:** Requested number of parallel plaso worker processes; the effective count is bounded by min(cpu_count - 1, this value).
- **Effect:** Raising it increases parallelism / throughput on big hosts (faster timelines) but raises CPU and especially memory pressure — the code's OOM remediation message suggests lowering it or raising AGENTROPIX_MEM_LIMIT_MB. Lowering it reduces resource use and OOM risk at the cost of slower runs. Effective value never exceeds cpu_count-1.

### `AGENTROPIX_PREFETCH_TIMEOUT`
- **Default:** `60.0 (seconds; floor 5.0, ceiling 3600.0)`
- **Purpose:** Wall-clock timeout (seconds) for the Windows prefetch (.pf) parser subprocess; read via get_float when no explicit timeout is passed.
- **Effect:** Raise for slow/large prefetch sets; lower to fail fast. Clamped to floor 5.0, ceiling 3600.0. Prefetch parsing is fast, hence the low default.

### `AGENTROPIX_PSORT_TIMEOUT`
- **Default:** `5400.0 (seconds)`
- **Purpose:** Wall-clock timeout (seconds) for the separate psort post-processing step that sorts/outputs the plaso storage file. Read via get_float with floor=30.0, ceiling=7200.0.
- **Effect:** Raising it gives psort more time to sort very large storage files (fewer psort WRAPPER_TIMEOUTs on big images) with longer worst-case hangs. Lowering it fails fast but may abort sorting of large timelines. Floor 30s, ceiling 7200s. Tuned independently from the log2timeline timeout because psort can need more time after a raised TIMEOUT_CAP.

### `AGENTROPIX_RADARE2_MAX_RESULTS`
- **Default:** `1000`
- **Purpose:** Caps the number of result rows (e.g. imports/exports/strings) returned from a rabin2 query.
- **Effect:** Raising returns more results (better recall on large binaries) but bigger payloads/slower; lowering truncates. Clamped to 1..100000.

### `AGENTROPIX_RADARE2_TIMEOUT`
- **Default:** `120.0 seconds`
- **Purpose:** Subprocess timeout (seconds) for the rabin2 invocation.
- **Effect:** Raising tolerates analysis of large/packed binaries; lowering fails slow runs faster. Clamped to floor 5.0, ceiling 3600.0.

### `AGENTROPIX_RATE_LIMIT`
- **Default:** `60`
- **Purpose:** Global default rate limit in calls-per-minute for the _RateLimiter guarding MCP tools.
- **Effect:** Raising permits more calls/min (higher throughput, more load/DoS exposure); lowering throttles harder. Per-tool overrides exist via AGENTROPIX_RATE_LIMIT_<TOOL_NAME>. get_int floor=1, ceiling=10000.

### `AGENTROPIX_RECMD_MAX_ENTRIES`
- **Default:** `10000 (10_000; floor 1, ceiling 1_000_000)`
- **Purpose:** Upper bound on the number of registry entries RECmd output rows the wrapper will ingest/return; read via get_int.
- **Effect:** Raise to capture more registry rows from huge hives (more recall, larger payload/memory); lower to bound output. Clamped to floor 1, ceiling 1000000.

### `AGENTROPIX_RECMD_TIMEOUT`
- **Default:** `120.0 (seconds; floor 5.0, ceiling 3600.0)`
- **Purpose:** Wall-clock timeout (seconds) for a RECmd registry-batch subprocess run; read via get_float when the caller passes no explicit timeout.
- **Effect:** Raise for large registry hives / big batch files that take longer to parse; lower to fail fast. Clamped to floor 5.0, ceiling 3600.0. Too low aborts legitimate parsing (recall loss); too high lets a stuck run block.

### `AGENTROPIX_REGRIPPER_RAW_CAP`
- **Default:** `8000`
- **Purpose:** Cap on the amount of raw RegRipper output retained/returned (character/byte cap).
- **Effect:** Raising keeps more raw output (more detail, larger payloads); lowering truncates noisy output. get_int floor=2000, ceiling=64000.

### `AGENTROPIX_REGRIPPER_TIMEOUT`
- **Default:** `60.0`
- **Purpose:** Subprocess timeout in seconds for a RegRipper run.
- **Effect:** Raising lets RegRipper finish on large hives (recall, longer hold); lowering aborts slow runs. get_float floor=5.0, ceiling=3600.0.

### `AGENTROPIX_SBECMD_MAX_ENTRIES`
- **Default:** `50000`
- **Purpose:** Cap on the number of shellbag entries SBECmd output is parsed/returned for.
- **Effect:** Raising it captures more shellbag history (more complete, larger output, slower); lowering it truncates (faster, may drop entries). Clamped to [1, 5000000].

### `AGENTROPIX_SBECMD_TIMEOUT`
- **Default:** `180.0`
- **Purpose:** Wall-clock timeout (seconds) for the SBECmd (dotnet) subprocess.
- **Effect:** Raising it allows large registry parses to finish (risk of hangs); lowering it aborts slow runs sooner. Clamped to [5.0, 3600.0].

### `AGENTROPIX_SHIMCACHE_TIMEOUT`
- **Default:** `60.0 seconds`
- **Purpose:** Subprocess timeout (seconds) for running the Shimcache (AppCompatCache) parser.
- **Effect:** Raising allows parsing large registry hives; lowering aborts slow runs sooner. Clamped to floor 5.0, ceiling 3600.0.

### `AGENTROPIX_SQLECMD_SAMPLE_PER_SCHEMA`
- **Default:** `100 (floor 1, ceiling 100_000)`
- **Purpose:** Number of sample rows retained per matched schema/map in SQLECmd output; read via get_int.
- **Effect:** Raise to keep more example rows per schema (richer evidence, larger payload/memory); lower to keep reports compact. Clamped to floor 1, ceiling 100000.

### `AGENTROPIX_SQLECMD_TIMEOUT`
- **Default:** `600.0 (seconds; floor 5.0, ceiling 3600.0)`
- **Purpose:** Wall-clock timeout (seconds) for a SQLECmd run over SQLite databases; read via get_float when no explicit timeout is passed.
- **Effect:** Raise for large databases / many maps; lower to fail fast. Clamped to floor 5.0, ceiling 3600.0. Too low aborts legitimate parsing (recall loss).

### `AGENTROPIX_SRUM_TIMEOUT`
- **Default:** `600.0 seconds`
- **Purpose:** Wall-clock timeout (seconds) for the SRUM-database export subprocess (esedbexport).
- **Effect:** Raise to allow large SRUDB.dat exports to complete (better recall, longer worst case); lower to fail fast. Clamped floor 5s, ceiling 3600s.

### `AGENTROPIX_STRINGS_MAX_RESULTS`
- **Default:** `1000`
- **Purpose:** Cap on how many extracted strings are returned from a single invocation.
- **Effect:** Raising it returns more output (more complete, larger payloads, slower); lowering it truncates results (faster, may drop relevant strings). Clamped to [1, 1000000].

### `AGENTROPIX_STRINGS_MIN_LENGTH`
- **Default:** `4`
- **Purpose:** Minimum sequence length passed to 'strings' (-n) for a byte run to be reported as a printable string.
- **Effect:** Raising it yields fewer, longer (higher-signal) strings — may miss short IOCs; lowering it surfaces more short strings (more noise, more recall). Clamped to [1, 1024].

### `AGENTROPIX_STRINGS_TIMEOUT`
- **Default:** `120.0`
- **Purpose:** Wall-clock timeout (seconds) for the strings subprocess.
- **Effect:** Raising it allows scanning larger files to completion (risk of long hangs); lowering it kills slow runs sooner (faster failure, may abort large legitimate scans). Clamped to [5.0, 3600.0].

### `AGENTROPIX_STRINGS_TOOL`
- **Default:** `strings`
- **Purpose:** Name/path of the GNU binutils 'strings' binary the wrapper invokes.
- **Effect:** Override to point at a non-default strings binary (e.g. a full path or busybox variant). If unset, uses DEFAULT_TOOL_NAME 'strings' from PATH. String, no clamp.

### `AGENTROPIX_SUSPICIOUS_FILES_FILE`
- **Default:** `"" (unset — falls back to AGENTROPIX_FS_SUSPICIOUS_FILENAMES / built-in defaults)`
- **Purpose:** Path to an operator-supplied file listing suspicious filenames; highest-priority source for filename matchers when the path is set AND exists.
- **Effect:** When set to an existing file it OVERRIDES both the inline env list and the built-in defaults. File format: blank/# lines ignored; lines prefixed 're:' compile as case-insensitive regex (enables pattern matching the inline var cannot); other lines are lowercased literals. If the path is unset or missing, it silently falls back to the inline var/defaults. Lets analysts maintain a richer, regex-capable IOC list. Default: unset (empty string).

### `AGENTROPIX_T1059_EVTX_TIMEOUT`
- **Default:** `180.0 seconds`
- **Purpose:** Subprocess timeout (seconds) for parsing EVTX event logs in the T1059.001 IEX loopback C2 detector.
- **Effect:** Raising allows full parsing of large EVTX (fewer missed events, better recall) but slower; lowering caps per-log time. Clamped to floor 5.0, ceiling 3600.0.

### `AGENTROPIX_T1059_MAX_EVENTS`
- **Default:** `5000 events`
- **Purpose:** Maximum number of EVTX events the detector will ingest/scan per run.
- **Effect:** Raising scans deeper into noisy logs (better recall, risk of truncation findings avoided) at cost of speed/memory; lowering bounds work but may truncate (detector emits a truncation finding). Clamped to 100..100000.

### `AGENTROPIX_TASKS_LIST_TIMEOUT`
- **Default:** `180.0 seconds`
- **Purpose:** Timeout in seconds for the scheduled-tasks listing operation (used when the timeout argument is None).
- **Effect:** Raising allows enumeration on large/slow images to finish; lowering fails fast. Clamped floor 5.0, ceiling 3600.0.

### `AGENTROPIX_TIMELINE_MAX_EVENTS`
- **Default:** `2000 (_DEFAULT_MAX_EVENTS)`
- **Purpose:** Maximum number of timeline events the agent ingests/considers (the plaso sampler's event-window budget). An explicit max_events constructor kwarg overrides this env var.
- **Effect:** Raising lets more events through the per-parser sampler (better recall of low-frequency high-signal events) but increases processing time/memory and can approach the agent finding cap; lowering speeds up but may sample out evidence. Default 2000 (bumped from 500) gives the sampler headroom for priority allocation (200) + round-robin across the 6 default parsers. Clamped floor 1, ceiling 100000.

### `AGENTROPIX_TRACE_RAW_MAX_BYTES`
- **Default:** `4096 (4 KiB; _DEFAULT_RAW_MAX_BYTES=4096; floor 256 B, ceiling 1 MiB = 1048576)`
- **Purpose:** Byte cap on raw text captured into trace 'snapshot' records (bounds how much raw tool I/O the trace stores).
- **Effect:** Raise to capture more raw context per trace event (better forensic/debug visibility, larger trace volume and potential to retain more sensitive raw data); lower to keep traces lean and limit data retention. Clamped to floor 256 B, ceiling 1 MiB; malformed/unset value falls back to default.

### `AGENTROPIX_TSK_MAX_READ_BYTES`
- **Default:** `52428800 (_DEFAULT_TSK_MAX_READ_BYTES = 50 * 1024 * 1024 = 50 MiB)`
- **Purpose:** Cap on bytes read from a file backing a TSK inode (via pytsk3) for hashing T1105 staged-binary indicators; files larger than the cap return b"" (skipped, not truncated).
- **Effect:** Raise to hash larger suspect binaries (more coverage, more memory/IO); lower to skip big files sooner. Deliberately skips-rather-than-truncates so SHA-256 stays valid for VirusTotal/threat-intel pivots — raising it brings bigger files into scope. Clamped floor 1 MiB, ceiling 500 MiB.

### `AGENTROPIX_TSK_TIMEOUT`
- **Default:** `60.0`
- **Purpose:** Wall-clock seconds budget for the Sleuth Kit fls filesystem-listing subprocess; on expiry fls is killed and TimeoutError raised.
- **Effect:** Raise for large recursive listings on big filesystems; lower to fail fast. Speed-vs-completeness on directory enumeration. Clamped floor 5.0, ceiling 3600.0.

### `AGENTROPIX_VOL3_TIMEOUT`
- **Default:** `600 (seconds) in run_volatility (_VOL3_TIMEOUT_DEFAULT=600, floor 5, ceiling 3600); 120.0 in the helper-dump path (_DEFAULT_VOL_TIMEOUT=120.0)`
- **Purpose:** Default per-call wall-clock timeout (seconds) for vol3 subprocess runs. Two code paths read it: _resolve_vol_timeout() (helper-dump paths, float) and _resolve_run_vol_timeout() for run_volatility() (int, with floor/ceiling via get_int).
- **Effect:** Raise to let heavy plugins (malfind, dlllist) on large 8-16 GiB Win10 dumps finish; lower to fail fast. In run_volatility() it is clamped to floor 5s / ceiling 3600s; in the helper path it is floored at 30s. Too low truncates legitimate analysis (recall loss / false 'failed'); too high lets a stuck run block the agent. Takes precedence over the deprecated AGENTROPIX_VOL_TIMEOUT.

### `AGENTROPIX_VOL_TIMEOUT`
- **Default:** `Unset; falls through to _DEFAULT_VOL_TIMEOUT=120.0 seconds`
- **Purpose:** Deprecated (W-142) legacy alias for the volatility subprocess timeout in seconds, read only by the _resolve_vol_timeout() helper path.
- **Effect:** Honored only if AGENTROPIX_VOL3_TIMEOUT is unset; emits a one-time deprecation warning. Value is floored at 30.0s. Same speed-vs-recall tradeoff as VOL3_TIMEOUT. Prefer AGENTROPIX_VOL3_TIMEOUT; this name may be removed.

### `AGENTROPIX_XXD_TIMEOUT`
- **Default:** `30.0`
- **Purpose:** Wall-clock seconds budget for the xxd subprocess; on expiry xxd is killed and TimeoutError raised.
- **Effect:** Raise to tolerate slow storage; lower to fail fast. Because output is bounded by length there is little streaming risk, so the default is modest. Clamped floor 1.0, ceiling 600.0.

### `AGENTROPIX_YARA_MAX_FILES`
- **Default:** `500 (_DEFAULT_MAX_FILES_PER_DIR)`
- **Purpose:** Per-directory cap on the number of files YARA will scan.
- **Effect:** Raising scans more files per dir (better recall, slower, more resource use); lowering bounds runtime but may skip evidence. get_int floor=10, ceiling=10000.

### `AGENTROPIX_YARA_MAX_FILE_SIZE_MB`
- **Default:** `50 (_DEFAULT_MAX_FILE_SIZE_MB)`
- **Purpose:** Maximum individual file size (in MB) eligible for YARA scanning; larger files are skipped.
- **Effect:** Raising scans bigger files (catches malware in large artifacts, slower/more memory); lowering skips large files for speed but may miss evidence. get_int floor=1, ceiling=2048.

### `AGENTROPIX_YARA_MAX_MATCHES`
- **Default:** `1000 (floor 1, ceiling 100_000)`
- **Purpose:** Cap on the number of YARA rule matches the wrapper returns from a scan; read via get_int.
- **Effect:** Raise to surface more matches on broadly-matching rules (more recall, larger payload); lower to bound output. Clamped to floor 1, ceiling 100000.

### `AGENTROPIX_YARA_SCAN_TIMEOUT_S`
- **Default:** `60 (_DEFAULT_SCAN_TIMEOUT_S)`
- **Purpose:** Wall-clock timeout in seconds for a YARA scan pass.
- **Effect:** Raising allows longer scans to complete (better recall on large targets, ties up the worker longer); lowering aborts slow scans sooner (faster, may truncate/miss results). get_int floor=5, ceiling=600.

### `AGENTROPIX_YARA_TIMEOUT`
- **Default:** `300.0 (seconds; floor 5.0, ceiling 3600.0)`
- **Purpose:** Wall-clock timeout (seconds) for a YARA scan subprocess. Read via get_float when no explicit timeout is given; an explicitly-passed timeout is clamped to the same bounds via clamp_float.
- **Effect:** Raise for scanning large targets / many rules; lower to fail fast. Clamped to floor 5.0, ceiling 3600.0 in both the env and explicit-arg paths. Too low aborts legitimate scans (recall loss).

## Detection tuning (confidence/thresholds)  (18)

### `AGENTROPIX_ARTIFACT_COC_CONFIDENCE`
- **Default:** `0.5`
- **Purpose:** Confidence score (0.0-1.0) stamped on ordinary chain-of-custody / artifact-parsed findings emitted by the ArtifactAgent.
- **Effect:** Raising it makes routine artifact findings rank/weight higher in downstream triage and scoring; lowering it de-emphasizes them. No speed cost. Set artificially high and benign findings drown out real signal; too low and they may be filtered out. Clamped to [0.0, 1.0].

### `AGENTROPIX_ARTIFACT_SUSPICIOUS_CONFIDENCE`
- **Default:** `0.6`
- **Purpose:** Confidence score (0.0-1.0) stamped on findings the ArtifactAgent flags as suspicious (vs. routine).
- **Effect:** Raising it makes suspicious findings weigh more heavily in scoring/alerting (good for not missing threats, risks more false-positive prominence); lowering it softens them. Note it defaults higher than the routine CoC confidence (0.6 vs 0.5), reflecting suspicious findings being treated as more important. Clamped to [0.0, 1.0].

### `AGENTROPIX_CRITIC_HALT_THRESHOLD`
- **Default:** `0.85 (_DEFAULT_HALT_THRESHOLD)`
- **Purpose:** Score threshold at/above which the Critic halts the Trinity (architect→swarm→critic) iteration loop. The score blends the highest per-finding confidence and cross-agent correlation count.
- **Effect:** Lower it to halt earlier (fewer iterations, faster, but may stop before the swarm fully explores → lower recall); raise it to demand stronger evidence before stopping (more thorough, slower/more LLM+tool cost). Clamped floor 0.0, ceiling 1.0. Default 0.85 halts on a high-confidence single finding or any correlated multi-agent agreement.

### `AGENTROPIX_DISC_MIN_CONFIDENCE`
- **Default:** `0.65`
- **Purpose:** Minimum confidence threshold for discovery-agent findings to be retained/surfaced. Bounded to [0.3, 1.0].
- **Effect:** Raising it keeps only high-confidence findings (higher precision, fewer false positives, but may drop true positives — lower recall). Lowering it surfaces more borderline findings (higher recall, more noise/false positives). Clamped [0.3, 1.0].

### `AGENTROPIX_FS_DELETED_CONFIDENCE`
- **Default:** `0.6`
- **Purpose:** Confidence score assigned to findings emitted for deleted/unallocated filesystem entries.
- **Effect:** Raise to make deleted-entry findings rank higher (more likely to drive the Trinity halt/triage); lower to de-prioritize them. Pure scoring weight, clamped floor 0.0, ceiling 1.0.

### `AGENTROPIX_FS_SUSPICIOUS_CONFIDENCE`
- **Default:** `0.85`
- **Purpose:** Confidence score assigned to findings where a filename matches the known-bad / suspicious-name matcher list.
- **Effect:** Raise to make suspicious-filename hits rank very high (stronger triage/halt signal); lower to soften. Pure scoring weight, clamped floor 0.0, ceiling 1.0. Default is high because a name match is a strong indicator.

### `AGENTROPIX_HUNT_CONFIDENCE_BONUS`
- **Default:** `0.1`
- **Purpose:** Additive confidence increment the HuntAgent applies to a correlation-derived finding (the per-correlation boost).
- **Effect:** Raising makes cross-agent correlations push confidence up faster (more aggressive escalation, risk of over-confidence on weak correlations); lowering makes correlation boosts gentler. Clamped 0.0-1.0.

### `AGENTROPIX_HUNT_CONFIDENCE_CAP`
- **Default:** `0.95`
- **Purpose:** Upper ceiling on the confidence a HuntAgent finding can reach after correlation bonuses are applied.
- **Effect:** Raising allows hunt findings to reach near-certainty (e.g. 1.0); lowering keeps a deliberate confidence headroom/reserve so correlated findings never assert full certainty. Clamped 0.0-1.0.

### `AGENTROPIX_INJECTION_CONFIDENCE_FLOOR`
- **Default:** `0.70`
- **Purpose:** Minimum per-indicator confidence required for a classified malfind hit to be kept as an injection indicator; read via get_float.
- **Effect:** Hits whose classifier confidence is below the floor are dropped before reporting. Raise toward 1.0 => fewer, higher-confidence injection findings (higher precision, lower recall — may miss subtle injection); lower toward 0.0 => more findings including weak signals (higher recall, more false positives). Clamped to floor 0.0, ceiling 1.0. Note: multi-indicator same-PID corroboration boosts confidence (+0.05, capped 0.97) AFTER this gate.

### `AGENTROPIX_MAIL_LOOKALIKE_DISTANCE`
- **Default:** `2 (_DEFAULT_LOOKALIKE_DISTANCE)`
- **Purpose:** Levenshtein/edit-distance floor passed to detect_lookalike_sender for flagging look-alike (typosquatted) sender domains as MITRE T1566.
- **Effect:** Raise to treat domains differing by more characters as look-alikes (more permissive matching, higher recall, more false positives); lower for stricter near-exact matches (higher precision, may miss). Precision/recall tradeoff. Clamped floor 1, ceiling 5.

### `AGENTROPIX_MEMORY_ORPHAN_CONFIDENCE`
- **Default:** `0.55`
- **Purpose:** Confidence score assigned to findings for orphaned processes (processes whose parent is missing / not in the kernel-PPID set).
- **Effect:** Raising it elevates orphan-process findings; lowering it treats orphans as weaker signal. Set lower than suspicious (0.55 vs 0.85) because orphaning is a softer indicator. Clamped to [0.0, 1.0].

### `AGENTROPIX_MEMORY_SUSPICIOUS_CONFIDENCE`
- **Default:** `0.85`
- **Purpose:** Confidence score assigned to findings for suspicious memory processes (e.g. name/pattern matches against the proc matchers).
- **Effect:** Raising it makes suspicious-process findings rank as higher-confidence (more likely to survive finding caps / draw analyst attention); lowering it de-emphasizes them. Clamped to [0.0, 1.0].

### `AGENTROPIX_NULL_SESSION_ABS_FLOOR`
- **Default:** `20`
- **Purpose:** Absolute per-hour event-count floor used as a minimum alerting threshold so the detector still fires on a cold/degenerate baseline; threshold = max(mean + z*stddev, ABS_FLOOR/10) live, or ABS_FLOOR when no live baseline. Data-driven separator (20/hour) calibrated from the SRL-2018 corpus.
- **Effect:** Raising it suppresses low-volume enumeration (fewer false positives, misses slow scans); lowering it catches quieter recon at the cost of noise on benign hosts. Clamped to [5, 100000].

### `AGENTROPIX_NULL_SESSION_Z_THRESHOLD`
- **Default:** `3.0`
- **Purpose:** Number of standard deviations above the learned per-IP-per-hour baseline mean that a logon-event (Security 4624) count must exceed to be flagged as anomalous null-session enumeration.
- **Effect:** Raising it makes the detector more conservative (fewer false positives, lower recall — quiet recon can slip under); lowering it flags more spikes (higher recall, more noise). Clamped to [2.0, 6.0].

### `AGENTROPIX_T1071_SVCHOST_CONFIDENCE`
- **Default:** `0.85 (_DEFAULT_CONFIDENCE)`
- **Purpose:** Confidence score assigned to T1071.001 svchost-outbound-HTTP (PlugX/Korplug-shaped C2) findings emitted by this detector. Read via get_float, clamped to [0.0, 1.0].
- **Effect:** Raising it makes these findings rank/alert more strongly (more likely to surface and trigger downstream thresholds, risk of overweighting if the detector is noisy in your environment). Lowering it de-emphasizes them (fewer escalations, risk of missing real C2). Does not change which events match — only the score on matches. Clamped [0,1].

### `AGENTROPIX_TIMELINE_LOLBIN_CONFIDENCE`
- **Default:** `0.7`
- **Purpose:** Confidence score (0.0-1.0) assigned to findings raised from a LOLBin keyword match in the timeline.
- **Effect:** Higher value makes LOLBin hits weigh more heavily in correlation/triage (more aggressive escalation, risk of false-positive prominence); lower de-prioritizes them. Clamped 0.0-1.0.

### `AGENTROPIX_YARA_CONFIDENCE_FLOOR`
- **Default:** `0.75`
- **Purpose:** Minimum confidence score (0.0-1.0) a YARA match must reach before yara_hunt reports it as a finding.
- **Effect:** Raising suppresses low-confidence matches (higher precision, lower recall — may miss real malware); lowering surfaces more matches (higher recall, more false positives). Read via get_float with floor=0.0, ceiling=1.0.

### `AGENTROPIX_YARA_FORGE_MIN_QUALITY`
- **Default:** `75 (_DEFAULT_FORGE_MIN_QUALITY)`
- **Purpose:** Minimum YARA-Forge rule quality score (0-100) for a Forge-bundle rule to be loaded/used during scanning.
- **Effect:** Raising keeps only high-quality community rules (fewer noisy hits, less recall); lowering admits lower-quality rules (more coverage, more false positives). get_int clamped floor=0, ceiling=100.

## Security / Egress / Gates  (17)

### `AGENTROPIX_ALLOW_EGRESS`
- **Default:** `unset → egress NOT allowed (only the literal string '1' enables it)`
- **Purpose:** Master network egress kill-switch for threat-intel lookups. All outbound TI API calls require this to be exactly '1'; default posture is air-gapped/offline.
- **Effect:** On ('1'): permits outbound calls to VirusTotal/OTX etc. (enables enrichment, but leaks indicators to third parties and requires network — a security/OPSEC tradeoff). Off (default): all TI network calls are refused, keeping the analysis air-gapped. Security gate, not a tuning knob.

### `AGENTROPIX_APPROVAL_SIDECAR_URL`
- **Default:** `http://127.0.0.1:8800`
- **Purpose:** Base URL of the human-approval sidecar service the server queries to gate sensitive/approval-required actions.
- **Effect:** Point at the approval sidecar host:port. If the sidecar is unreachable, approval-gated operations cannot proceed. Same default used in fastmcp_app.py.

### `AGENTROPIX_EVIDENCE_SHA256`
- **Default:** `"" (unset — inline hashing is performed unless the size cap is exceeded)`
- **Purpose:** Operator-supplied precomputed SHA-256 (64-char hex) of the evidence image, embedded into the chain-of-custody record instead of hashing inline.
- **Effect:** Set it to skip the potentially expensive inline hash (used when the image is huge or already verified) while still recording an authoritative hash for court. Must be exactly 64 hex chars or it is ignored with a warning. Default unset means the tool computes the hash itself (subject to the size cap below). Security/integrity-sensitive: a wrong value misrepresents custody.

### `AGENTROPIX_EVT_MAX_EVENTS`
- **Default:** `5000`
- **Purpose:** Caps the number of Windows event-log records parsed/returned per evtexport invocation.
- **Effect:** Raising it returns more events (better timeline completeness/recall, larger output and slower); lowering it truncates the event set, faster and lighter but may drop relevant entries. Clamped to [1, 100000].

### `AGENTROPIX_EVT_TIMEOUT`
- **Default:** `300.0 seconds`
- **Purpose:** Subprocess timeout (seconds) for the evtexport event-log export call.
- **Effect:** Raising it tolerates slow exports on large/corrupt logs before aborting; lowering it fails fast. Clamped to [5.0, 3600.0] seconds.

### `AGENTROPIX_MCP_AUTH_TOKEN`
- **Default:** `None (unset — boot fails closed unless dev mode opt-in)`
- **Purpose:** Bearer token required to authenticate every HTTP POST to the /mcp endpoint.
- **Effect:** Must be a strong random token (32+ bytes recommended). If unset the server fails closed at boot (RuntimeError, refuses to start) UNLESS AGENTROPIX_MCP_DEV_MODE=1 is also set. Security-critical: without it the server would accept unauthenticated requests.

### `AGENTROPIX_MCP_DEV_MODE`
- **Default:** `unset (only '1' enables dev mode)`
- **Purpose:** Explicit opt-in to run the MCP server unauthenticated when no auth token is set.
- **Effect:** When ='1' and AGENTROPIX_MCP_AUTH_TOKEN is unset, the server starts unauthenticated and emits a RuntimeWarning ('NEVER use in production'). Any other value (or unset) keeps the fail-closed boot. Security tradeoff: enabling disables auth entirely.

### `AGENTROPIX_OTX_API_KEY`
- **Default:** `"" (empty string — no key, OTX lookups effectively unavailable)`
- **Purpose:** API key/credential used to authenticate to AlienVault OTX for threat-intel enrichment.
- **Effect:** Set it to enable authenticated OTX queries (requires AGENTROPIX_ALLOW_EGRESS=1 too). Empty disables OTX enrichment. Secret — handle as a credential; presence/absence controls whether the OTX provider can run, not result quality directly.

### `AGENTROPIX_THYMUS_ALLOWED_PREFIXES`
- **Default:** `"" (empty -> no extra prefixes beyond READONLY_PATHS)`
- **Purpose:** Operator-supplied comma- or colon-separated list of extra path prefixes to pre-allow in the Thymus read policy (e.g. a per-case dataset dir).
- **Effect:** Adding prefixes widens what paths tools may access (needed to reach case data, but loosens the security boundary). Each entry is trimmed and normalized to end with '/'; empty entries dropped. More entries = broader access.

### `AGENTROPIX_THYMUS_AUDIT_LOG_RING_SIZE`
- **Default:** `1000 (_AUDIT_LOG_RING_DEFAULT)`
- **Purpose:** Size of the in-memory ring buffer (deque maxlen) retaining recent Thymus policy audit entries. The authoritative chain is the on-disk JSONL AGENTROPIX_AUDIT_LOG; this ring is just the in-memory tail.
- **Effect:** Raising keeps more recent decisions queryable in memory (more forensic context, more RAM); lowering drops older entries sooner. Clamped to 100..100000.

### `AGENTROPIX_TIMELINE_EVIDENCE_MSG_CHARS`
- **Default:** `600`
- **Purpose:** Truncation length of the raw 'msg' field embedded in a finding's evidence string. Default 600 chars is tuned to capture TargetUserName/TargetDomainName/IpAddress in 4624 logon events, which sit ~250-400 chars deep.
- **Effect:** Raising preserves more of the event body in evidence (richer forensic context, e.g. logon target fields) at the cost of larger findings; lowering risks cutting off diagnostic fields. Ceiling 4000 prevents OOM on pathological blobs. Clamped floor 80, ceiling 4000.

### `AGENTROPIX_TI_PROVIDERS`
- **Default:** `virustotal,otx (both)`
- **Purpose:** Comma-separated allowlist selecting which threat-intel providers are queried.
- **Effect:** Restricting to one provider reduces external calls/latency and limits which third parties see your indicators (faster, tighter OPSEC) but reduces enrichment coverage. Listing both maximizes coverage at the cost of more egress and latency.

### `AGENTROPIX_TI_TIMEOUT`
- **Default:** `60.0 (_DEFAULT_TIMEOUT_S)`
- **Purpose:** Per-request HTTP timeout (seconds) for threat-intel API calls. Read via get_float with floor=30, ceiling=300; can be overridden per-call by a timeout argument.
- **Effect:** Raising it tolerates slow TI APIs (fewer failed lookups, but slower overall and longer worst-case stall). Lowering it fails fast on unresponsive providers (snappier, but may abandon enrichment that would have succeeded). Clamped to [30, 300]s.

### `AGENTROPIX_TOKEN_ALLOWLIST`
- **Default:** `"pe,ps,rc4,asm,cs,rdp,iis,ftp" (_DEFAULT_SHORT_TOKEN_ALLOWLIST)`
- **Purpose:** Comma-separated, case-insensitive list of short security-relevant tokens (e.g. pe, ps, rc4, rdp) that are allowed to participate in cross-agent correlation EVEN when shorter than AGENTROPIX_TOKEN_MIN_LENGTH. Matched with non-word boundaries so 'pe' hits 'PE.exe' but not 'append'.
- **Effect:** Extending it lets more short identifiers form correlations (higher recall on 2-char IOCs, but more risk of noisy/false correlations); narrowing reduces noise; an empty string disables the short-token allowlist entirely (those short tokens then never correlate). Split on commas, blanks dropped, lowercased.

### `AGENTROPIX_TOKEN_MIN_LENGTH`
- **Default:** `3 (floor 1, ceiling 10)`
- **Purpose:** Minimum token length for the main correlation tokenizer regex [A-Za-z0-9_.\-]{N,}; tokens shorter than N are ignored when extracting filenames/PIDs/hashes/URLs from finding evidence (except allowlisted short tokens).
- **Effect:** Lowering captures shorter tokens (higher correlation recall, but more spurious cross-agent matches and noise); raising demands longer tokens (higher precision, fewer false correlations, but may miss short identifiers not on the allowlist). Clamped to floor=1, ceiling=10 via get_int.

### `AGENTROPIX_VERIFY_TOOL_PINS`
- **Default:** `warn`
- **Purpose:** Trust mode controlling SHA-256 pin verification of external forensic binaries (verifies that resolved tool binaries match their pinned hashes). Value lower-cased/stripped; accepts 'off','warn','strict' (unknown values warn and fall back to 'warn').
- **Effect:** 'strict' enforces pins (mismatched binaries are treated as failures — strongest supply-chain integrity, but a single hash mismatch can block runs). 'warn' (default) logs mismatches but proceeds. 'off' skips verification entirely (fastest, but no tamper detection — weakest security). Security/integrity knob; flags only mismatches, not missing tools.

### `AGENTROPIX_VT_API_KEY`
- **Default:** `"" (empty string — no key, VT lookups effectively unavailable)`
- **Purpose:** API key/credential used to authenticate to VirusTotal for threat-intel enrichment.
- **Effect:** Set to enable authenticated VirusTotal queries (also needs AGENTROPIX_ALLOW_EGRESS=1). Empty disables the VT provider. Secret — treat as a credential.

## Wazuh / Integration  (1)

### `WAZUH_INDEXER_TLS_VERIFY`
- **Default:** `"true" (TLS verification ON / strict)`
- **Purpose:** Controls whether TLS certificate verification is enforced on connections to the Wazuh indexer from the approval-sidecar writer/health paths.
- **Effect:** Default strict (true): certificates are verified — secure. Setting it falsey (the raw value is lowercased and compared) disables verification to allow self-signed/dev certs, which is a security downgrade vulnerable to MITM and should not be used in production. Same env var honored in both the writer and a health-check path (per SIFT-W-296).

## Tool paths / data files / sets  (54)

### `AGENTROPIX_7Z_TOOL`
- **Default:** `7z (DEFAULT_7Z; resolved via shutil.which on PATH)`
- **Purpose:** Name/path of the 7-Zip binary used both for the no-extract pre-flight inventory (7z l -slt) and for extracting .7z/.zip/.rar archives.
- **Effect:** Point at an alternate 7z build/path (e.g. for a patched or pinned p7zip). Wrong value makes pre-flight and 7z-engine extraction fail with FileNotFoundError; no recall/speed tradeoff, purely binary selection.

### `AGENTROPIX_ACTIVE_CASE_DIR`
- **Default:** `~/.agentropix (ACTIVE_CASE_DIR_DEFAULT)`
- **Purpose:** Base directory where the active-case pointer file (active_case) is stored; primarily so tests can redirect to a tempdir.
- **Effect:** Set to relocate the active-case state directory (e.g. isolate per test or per operator). No recall/speed tradeoff; wrong path can lose track of the active case.

### `AGENTROPIX_AMCACHE_TOOL`
- **Default:** `amcache_parser (DEFAULT_TOOL_NAME; resolved via shutil.which on PATH)`
- **Purpose:** Name/path of the Amcache parser binary invoked on the hive (output parsed as CSV or key-value text).
- **Effect:** Override to point at a specific parser (e.g. Eric Zimmerman's AmcacheParser under Wine). If not found on PATH the wrapper does NOT raise — it returns a graceful-skip report (tool_available=False, populated skip_reason), so a wrong/missing value silently disables Amcache findings rather than erroring. Binary selection.

### `AGENTROPIX_ARTIFACT_FORMATS`
- **Default:** `{.e01, .ex01, .lx01, .l01} (_DEFAULT_E01_SUFFIXES)`
- **Purpose:** Comma-separated override for the EWF/disk-image (E01-family) suffix set recognized as evidence containers (W-031 row 13).
- **Effect:** Lets operators add vendor-specific container extensions without code changes; live-read via get_e01_suffixes(). Malformed/unset preserves the four-token baseline. Expanding it makes more file types treated as disk images.

### `AGENTROPIX_AUDIT_LOG_DIR`
- **Default:** `/var/log/agentropix`
- **Purpose:** Directory where the MCP HTTP audit JSON log is written (SIFT-W-281; primarily for test isolation).
- **Effect:** Override to redirect audit logs (e.g. to a temp dir in tests) instead of the production /var/log/agentropix. Changing it moves the forensic request trail — point it at a persistent, access-controlled path in production.

### `AGENTROPIX_BE_TOOL`
- **Default:** `"bulk_extractor" (DEFAULT_TOOL_NAME)`
- **Purpose:** Name/path of the bulk_extractor binary to execute (resolved via shutil.which). Also used by the CLI doctor command to point at the same binary.
- **Effect:** Set to redirect to an alternate or libewf-enabled build (e.g. to scan EWF/E01 natively) or a non-PATH install; if the named binary is not on PATH the wrapper raises FileNotFoundError. No recall/speed tradeoff per se, but choosing a libewf-enabled binary changes EWF handling. Plain string, no clamping.

### `AGENTROPIX_DISK_SUFFIXES`
- **Default:** `{.dd, .raw, .img, .e01, .vmdk, .qcow2, .vhd, .vhdx, .aff4, .vdi} (_DEFAULT_DISK_SUFFIXES, 10 tokens)`
- **Purpose:** Override for the set of file suffixes classified as disk images during evidence triage.
- **Effect:** Set (comma-separated) to broaden/narrow what counts as a disk artifact; unset/malformed falls back to the ten-token default. Affects which inputs are routed through disk-image handling.

### `AGENTROPIX_DOTNET_TOOL`
- **Default:** `"dotnet"`
- **Purpose:** Name/path of the .NET runtime ('dotnet') used to launch the EZ Tools MFTECmd.dll (shared with LECmd and other EZ wrappers).
- **Effect:** Set to point at a specific dotnet install not on PATH; if not found, the wrapper does a graceful skip (tool_available=False, skip_reason advising install dotnet-runtime-9.0 or set this var) rather than erroring. Plain string, no clamping. DEFAULT_DOTNET.

### `AGENTROPIX_EVTEXPORT_TOOL`
- **Default:** `"evtexport" (DEFAULT_TOOL_NAME, resolved via PATH)`
- **Purpose:** Path/name of the 'evtexport' binary (libevtx) used to export Windows Event Log records.
- **Effect:** Override to point at a specific evtexport build or absolute path. Correctness/portability only; no performance tradeoff.

### `AGENTROPIX_EVTX_CACHE_DIR`
- **Default:** `~/.cache/agentropix-sift/evtx (Path.home()/.cache/agentropix-sift/evtx)`
- **Purpose:** Filesystem directory where parsed EVTX output is cached (LRU) so repeated event-log parses on the same image don't re-run the parser.
- **Effect:** Point it at a larger/faster volume to hold more cached parse results or relocate off a full disk; no recall/precision effect, purely a speed/storage-location knob. Created on first access.

### `AGENTROPIX_EVTX_TOOL`
- **Default:** `unset → auto-resolve: Rust 'evtx_dump' if on PATH, else 'evtx_dump.py' (DEFAULT_TOOL_NAME)`
- **Purpose:** Operator override that pins the EVTX parser binary/path. When unset, resolution prefers Rust 'evtx_dump' on PATH (~30x faster), else falls back to python-evtx 'evtx_dump.py'.
- **Effect:** Set to force a specific parser (e.g. pin to the Python parser, or an absolute path). Overriding to the Python parser disables JSONL-forcing and the workers cap (those are Rust-only features). Otherwise affects speed and which flags are usable.

### `AGENTROPIX_EWFMOUNT_TOOL`
- **Default:** `"ewfmount"`
- **Purpose:** Name/path of the ewfmount binary used to FUSE-mount EWF/E01 images (the deb bulk_extractor lacks libewf).
- **Effect:** Set to point at a non-PATH or alternate ewfmount; if absent, EWF/E01 targets raise a RuntimeError advising to install ewf-tools, pre-convert with ewfexport, or set AGENTROPIX_BE_TOOL to a libewf-enabled binary. Plain string, no clamping.

### `AGENTROPIX_EWF_LIFECYCLE_DIR`
- **Default:** `"" (empty -> built-in default scratch dir; read at line 209 via os.environ.get with default "")`
- **Purpose:** Base scratch directory for the ewf and mnt mount points created during the lifecycle.
- **Effect:** Set to relocate scratch mounts (e.g. to a large/fast volume). Empty string means the code's built-in default scratch location is used.

### `AGENTROPIX_EXIFTOOL_TOOL`
- **Default:** `exiftool (DEFAULT_TOOL_NAME)`
- **Purpose:** Name (or path) of the exiftool executable to resolve via PATH (shutil.which).
- **Effect:** Override to point at a specific/renamed exiftool binary; if not found on PATH the wrapper raises with a hint to install exiftool or set this var. No tradeoff — purely tool resolution.

### `AGENTROPIX_FLS_TOOL`
- **Default:** `fls`
- **Purpose:** Name/path of the Sleuth Kit `fls` executable used to list filesystem entries when enumerating scheduled-task artifacts.
- **Effect:** Override to point at a specific fls binary; no behavioral tradeoff — purely tool resolution. (Sibling AGENTROPIX_IFIND_TOOL similarly defaults to 'ifind'.)

### `AGENTROPIX_FOREMOST_TOOL`
- **Default:** `"foremost" (DEFAULT_TOOL_NAME)`
- **Purpose:** Override for the foremost binary name/path used by the wrapper.
- **Effect:** Set to pin a specific foremost install or absolute path. No tradeoff beyond which binary runs; if unresolved the wrapper errors prompting to set it.

### `AGENTROPIX_FUSERMOUNT_TOOL`
- **Default:** `"fusermount"`
- **Purpose:** Name/path of the fusermount binary used to unmount the EWF FUSE mount (resolved via shutil.which).
- **Effect:** Set to point at an alternate fusermount; if shutil.which can't find it, unmount is silently skipped (mount may be left dangling but no error surfaces). Plain string, no clamping.

### `AGENTROPIX_HASHDEEP_ALGOS`
- **Default:** `sha256,md5`
- **Purpose:** Comma-separated list of hash algorithms hashdeep computes over files (used as the default when the API caller doesn't pass algos).
- **Effect:** Add algorithms (e.g. 'sha256,md5,sha1') for broader cross-referencing against hash sets (more compute per file); reduce to one for speed. Comma-split string.

### `AGENTROPIX_HASHDEEP_TOOL`
- **Default:** `"hashdeep" (DEFAULT_TOOL_NAME)`
- **Purpose:** Override for the hashdeep binary name/path used by the wrapper.
- **Effect:** Set to pin a specific hashdeep install or absolute path (e.g. when not on PATH). No tradeoff beyond which binary runs; if unresolved the wrapper errors prompting to set it.

### `AGENTROPIX_HIVE_DIR`
- **Default:** `(empty string / unset)`
- **Purpose:** Directory where the operator stages the registry hive triple (SAM, SECURITY, SYSTEM) for the W-072/ADR-014 credential-triage secretsdump path. Read, stripped, from the environment (empty default).
- **Effect:** Must point at a dir containing all three hives or the secretsdump step gracefully skips ('no SAM/SECURITY/SYSTEM hive triple under AGENTROPIX_HIVE_DIR'). Security-sensitive: enables offline credential extraction. No default — empty unless set.

### `AGENTROPIX_ICAT_TOOL`
- **Default:** `"icat" (DEFAULT_ICAT, resolved via PATH)`
- **Purpose:** Path/name of the Sleuth Kit 'icat' binary used to extract file content by inode.
- **Effect:** Override to point at a specific/alternate icat build or absolute path (e.g. non-PATH install or a wrapper). Misconfiguration yields a FileNotFoundError ('install sleuthkit or set AGENTROPIX_ICAT_TOOL'). No perf tradeoff; correctness/portability only.

### `AGENTROPIX_IFIND_TOOL`
- **Default:** `"ifind" (DEFAULT_IFIND, resolved via PATH)`
- **Purpose:** Path/name of the Sleuth Kit 'ifind' binary used to locate inodes/files by name within an image.
- **Effect:** Override to select a specific ifind binary or absolute path. If unresolved, extraction raises FileNotFoundError prompting to install sleuthkit or set this var. Correctness/portability only.

### `AGENTROPIX_ISTAT_TOOL`
- **Default:** `"istat" (DEFAULT_ISTAT, resolved via PATH)`
- **Purpose:** Path/name of the Sleuth Kit 'istat' binary used to read inode metadata/stat details.
- **Effect:** Override to point at a specific istat binary or absolute path. Correctness/portability only; no performance impact.

### `AGENTROPIX_JLECMD_DLL`
- **Default:** `/opt/ezt/net9/JLECmd/JLECmd.dll (DEFAULT_DLL)`
- **Purpose:** Filesystem path to the JLECmd.dll (Eric Zimmerman jump-list parser) that the wrapper invokes via dotnet.
- **Effect:** Point it at a different install location/version of JLECmd. If the file is absent the wrapper raises an error advising to install the EZ Tools net9 zip or set this var. Path/deployment knob; no recall/precision effect.

### `AGENTROPIX_LECMD_DLL`
- **Default:** `"/opt/ezt/net9/LECmd/LECmd.dll"`
- **Purpose:** Filesystem path to the LECmd .NET DLL invoked as 'dotnet <dll>' to parse Windows .lnk shortcut files.
- **Effect:** Set to point at a non-default EZ Tools net9 install or specific LECmd version; if the file is absent, the wrapper gracefully skips (tool_available=False, skip_reason). Plain string path, no clamping. DEFAULT_DLL.

### `AGENTROPIX_MEMORY_SUFFIXES`
- **Default:** `{.mem, .vmem, .dmp, .lime, .memdump, .crash} (_DEFAULT_MEMORY_SUFFIXES, 6 tokens)`
- **Purpose:** Override for the set of file suffixes classified as memory dumps during evidence triage.
- **Effect:** Set (comma-separated) to broaden/narrow what counts as a memory artifact; unset/malformed falls back to the six-token default. Controls which inputs route to memory-analysis handling.

### `AGENTROPIX_MFTECMD_DLL`
- **Default:** `"/opt/ezt/net9/MFTECmd/MFTECmd.dll"`
- **Purpose:** Filesystem path to the MFTECmd .NET DLL invoked as 'dotnet <dll>' to parse NTFS artifacts ($MFT, $J, $I30, $Boot, $Secure).
- **Effect:** Set to point at a non-default EZ Tools net9 install location or a specific MFTECmd version; if the file is absent, the wrapper gracefully skips (tool_available=False, skip_reason). Plain string path, no clamping. DEFAULT_DLL.

### `AGENTROPIX_NULL_SESSION_BASELINE_DIR`
- **Default:** `Reports_results/_baselines/null_session`
- **Purpose:** Filesystem directory where computed per-host null-session baselines are persisted and read back.
- **Effect:** Changing it relocates baseline storage; pointing at an empty/wrong dir forces cold recomputation (no stale reuse, slower first run). Not numeric — string path, no clamp.

### `AGENTROPIX_PDFINFO_TOOL`
- **Default:** `pdfinfo (DEFAULT_PDFINFO)`
- **Purpose:** Names the pdfinfo binary used to read PDF metadata/page count before text extraction.
- **Effect:** Point at an alternate/absolute pdfinfo path if not on PATH. Changing it does not affect recall/speed; an invalid path makes the wrapper fail to read page counts/metadata.

### `AGENTROPIX_PDFTOTEXT_TOOL`
- **Default:** `pdftotext (DEFAULT_PDFTOTEXT)`
- **Purpose:** Names the pdftotext binary used to extract text from PDFs.
- **Effect:** Override to a specific build/path of pdftotext. Wrong value causes extraction to fail; no recall/speed tradeoff from the name itself.

### `AGENTROPIX_PLASO_PARSERS`
- **Default:** `winevtx,mft (the get_str_set fallback; only applied when the env var is set and non-empty)`
- **Purpose:** Comma-separated allowlist of plaso parsers to run (only consulted when the parsers kwarg is None). Parsed as a string-set then re-joined into the --parsers CLI arg.
- **Effect:** Narrowing to fewer parsers (e.g. just winevtx,mft) dramatically speeds up log2timeline and shrinks output (higher speed/precision for targeted hunts) but misses artifacts other parsers would surface (lower recall). Adding parsers broadens coverage at large time/CPU cost. Note: if the var is unset, plaso's own default parser selection is used, not this fallback.

### `AGENTROPIX_PREFETCH_TOOL`
- **Default:** `"pf" (DEFAULT_TOOL_NAME)`
- **Purpose:** Name or path of the prefetch-parser binary resolved via shutil.which (distros ship it as 'pf' or 'prefetch').
- **Effect:** Override to match the locally-installed parser name/path. Missing on PATH => error with install guidance. Just locates the tool; no precision tradeoff.

### `AGENTROPIX_RABIN2_TOOL`
- **Default:** `rabin2 (DEFAULT_TOOL_NAME)`
- **Purpose:** Names the rabin2 (radare2) binary used for binary triage/metadata extraction.
- **Effect:** Override to a specific rabin2 path/build. If not found on PATH and unset, the wrapper raises FileNotFoundError. No recall/speed tradeoff from the name.

### `AGENTROPIX_RECMD_BATCH_DIR`
- **Default:** `/opt/ezt/net9/RECmd/BatchExamples (DEFAULT_BATCH_DIR)`
- **Purpose:** Directory containing RECmd .reb batch files (the BatchExamples folder); used to resolve a relative batch name.
- **Effect:** Override to point at a custom batch-definition directory. A relative batch name is resolved against this dir; missing dir => error with install guidance. Controls which set of registry-extraction recipes is available.

### `AGENTROPIX_RECMD_DLL`
- **Default:** `/opt/ezt/net9/RECmd/RECmd.dll (DEFAULT_DLL)`
- **Purpose:** Filesystem path to the RECmd.dll (.NET EZ Tools net9 build) the dotnet runtime executes.
- **Effect:** Override when RECmd is installed somewhere other than the default EZ Tools path. If the path does not exist the wrapper errors with install guidance. No precision tradeoff — it just locates the tool binary.

### `AGENTROPIX_REPORT_OUTPUT_DIR`
- **Default:** `<tempdir>/agentropix-reports (e.g. /tmp/agentropix-reports)`
- **Purpose:** Directory where rendered report/export artifacts are written (local writes only, no network).
- **Effect:** Override to control where reports land; otherwise a stable temp subdir is used and created if missing. Set to a persistent path to retain reports across reboots.

### `AGENTROPIX_SBECMD_DLL`
- **Default:** `/opt/ezt/net9/SBECmd/SBECmd.dll`
- **Purpose:** Filesystem path to the EZ Tools SBECmd .NET DLL the wrapper runs via dotnet.
- **Effect:** Override to relocate the SBECmd install. If the DLL is absent at the resolved path the wrapper gracefully skips (tool_available=False) advising to set this var. String, no clamp.

### `AGENTROPIX_SECRETSDUMP_TOOL`
- **Default:** `unset → falls back to ('impacket-secretsdump.py', 'secretsdump.py')`
- **Purpose:** Override for the secretsdump executable name/path; if set, it is used as the sole candidate, otherwise the wrapper's default tool list is tried.
- **Effect:** Lets operators pin a specific binary. If unset, candidates fall back to DEFAULT_TOOLS = ('impacket-secretsdump.py', 'secretsdump.py') resolved on PATH. No clamp (string).

### `AGENTROPIX_SHIMCACHE_TOOL`
- **Default:** `shimcache_parser (DEFAULT_TOOL_NAME)`
- **Purpose:** Names the Shimcache/AppCompatCache parser binary.
- **Effect:** Override to point at an installed parser path. If unset and not on PATH, wrapper raises a FileNotFoundError instructing to install one or set this var.

### `AGENTROPIX_SQLECMD_DLL`
- **Default:** `/opt/ezt/net9/SQLECmd/SQLECmd.dll (DEFAULT_DLL)`
- **Purpose:** Filesystem path to SQLECmd.dll (.NET EZ Tools net9 build) executed by the dotnet runtime.
- **Effect:** Override when SQLECmd is installed elsewhere. Missing path => error with install guidance. Just locates the tool binary; no precision tradeoff.

### `AGENTROPIX_SQLECMD_MAPS_DIR`
- **Default:** `/opt/ezt/net9/SQLECmd/Maps (DEFAULT_MAPS_DIR)`
- **Purpose:** Directory of SQLECmd Maps (the .smap definitions that tell SQLECmd how to parse known SQLite databases).
- **Effect:** Override to use a custom/extended Maps directory. The available maps determine which SQLite artifacts (browser history, app DBs, etc.) get recognized and parsed => directly affects detection coverage. Missing dir => error.

### `AGENTROPIX_SRUM_TOOL`
- **Default:** `"esedbexport" (DEFAULT_TOOL_NAME)`
- **Purpose:** Override for the ESE/SRUM export binary used by the wrapper (esedbexport from libesedb).
- **Effect:** Set to pin a specific esedbexport install or absolute path. No tradeoff beyond which binary runs; if unresolved the wrapper errors prompting to set it.

### `AGENTROPIX_SUSPICIOUS_PROCS_FILE`
- **Default:** `"" (unset — falls back to AGENTROPIX_MEMORY_SUSPICIOUS_PROCS / built-in defaults)`
- **Purpose:** Path to an operator-supplied file listing suspicious process names; highest-priority source for process matchers when the path is set AND exists.
- **Effect:** When set to an existing file it OVERRIDES the inline env list and built-in defaults, and adds regex support (lines prefixed 're:' become case-insensitive patterns; '#'/blank ignored; others lowercased literals). Missing/unset path falls back silently to the inline var/defaults. Enables a maintainable regex-capable process IOC list. Default: unset.

### `AGENTROPIX_T1071_SVCHOST_ALLOWLIST_EXTRA`
- **Default:** `"" (empty — only the baseline MS allowlist + auto-ignore RFC1918/loopback CIDRs are used)`
- **Purpose:** Comma-separated extra CIDR ranges appended to the built-in Microsoft service-range allowlist used to whitelist legitimate svchost outbound HTTP destinations. Invalid CIDRs are logged and skipped.
- **Effect:** Adding CIDRs suppresses findings to those destinations (fewer false positives for known-good infra like your proxy/CDN, but risk of masking real C2 if you over-allowlist — lower recall). Empty keeps the conservative baseline. Precision/recall tradeoff knob.

### `AGENTROPIX_TAR_TOOL`
- **Default:** `tar (DEFAULT_TAR; resolved via shutil.which on PATH)`
- **Purpose:** Name/path of the tar binary used to extract .tar/.tgz/.tbz2/.txz/.tar.gz/.tar.bz2/.tar.xz archives (tar -xf, compression auto-detected).
- **Effect:** Override to select a specific (e.g. GNU) tar. Wrong value yields FileNotFoundError for tar-engine extractions; binary selection only, no recall/speed tradeoff.

### `AGENTROPIX_TIMELINE_LOLBINS`
- **Default:** `powershell, cmd.exe, wscript, cscript, mshta, regsvr32, rundll32, certutil, bitsadmin, schtasks (_DEFAULT_LOLBIN_KEYWORDS)`
- **Purpose:** Override set (read as a string set) of LOLBin keyword tokens whose presence in a timeline event's command line/message marks it as a living-off-the-land binary execution indicator.
- **Effect:** Adding keywords widens LOLBin detection (more recall for abuse of native tools); removing narrows it (fewer flags, risk of missing abuse). Replaces the built-in default set entirely when set.

### `AGENTROPIX_TIMELINE_PARSERS`
- **Default:** `winevtx,winreg,prefetch,winjob,mft (_DEFAULT_TIMELINE_PARSERS)`
- **Purpose:** Comma-separated list of plaso parsers to run for timelining. Resolved with floor/ceiling guards on count, then has AGENTROPIX_PLASO_EXCLUDE_FAMILIES subtracted.
- **Effect:** Adding parsers surfaces more artifact types (recall) but grows plaso storage and psort sort time; removing speeds up. Note filestat is deliberately excluded from the default because on a 12GB DC E01 it produces millions of events and overflowed psort's SQLite sort spill. Falls back to default on empty/invalid input or if count is outside floor 1 / ceiling 16.

### `AGENTROPIX_VOL26_BIN`
- **Default:** `"/opt/vol26/vol.py"`
- **Purpose:** Absolute path to the legacy Volatility 2.6 'vol.py' entry script run inside the Python 2.7 sandbox.
- **Effect:** Set to point at a non-default vol.py install; if the path does not exist, _require_sandbox raises FileNotFoundError pointing at docs/runbooks/vol26-install.md. Plain string path, no clamping. _DEFAULT_BIN.

### `AGENTROPIX_VOL26_PYTHON`
- **Default:** `"/opt/vol26/venv/bin/python"`
- **Purpose:** Path to the Python 2.7 interpreter (sandbox venv) that runs the legacy Volatility 2.6 editbox plugin out-of-process, isolating it from the SIFT Python 3.12 runtime.
- **Effect:** Set to point at a non-default Py2.7 venv; if the path does not exist, _require_sandbox raises FileNotFoundError with a runbook pointer. Plain string path, no clamping. _DEFAULT_PYTHON.

### `AGENTROPIX_W205_MASTER_IOCS_PATH`
- **Default:** `unset (None; os.environ.get with no default)`
- **Purpose:** Path to the W-205 MASTER-IOCS dataset used for the c4-F7 indeterminate cross-host consult (checks whether the host appears in skipped process-tree findings).
- **Effect:** When set (and a host is known), enables marking prereq state 'indeterminate' based on master IOCs; unset skips that consult, so cross-host correlation is lost. No speed cost when unset.

### `AGENTROPIX_W205_PREREQ_SIDECAR_DIR`
- **Default:** `unset -> fallback dir image.parent.parent / "_internal"`
- **Purpose:** Target directory for the LOCAL-only W-205 prerequisite-gap sidecar JSON files.
- **Effect:** Set to control where prereq_gaps_<host>.json sidecars are written. If unset, it falls back to image.parent.parent/_internal and logs a WARNING; setting it avoids polluting evidence dirs.

### `AGENTROPIX_XXD_TOOL`
- **Default:** `xxd (DEFAULT_TOOL_NAME; resolved via shutil.which on PATH)`
- **Purpose:** Name/path of the xxd binary used to render the hex dump.
- **Effect:** Override to point at a specific xxd (e.g. from vim-common). Wrong value raises FileNotFoundError. Binary selection only.

### `AGENTROPIX_YARA_RULES_DIR`
- **Default:** `"" (unset → bundled rules; in mcp_server/server.py default is /usr/share/yara/rules/)`
- **Purpose:** Operator override for the directory containing YARA rule files used by the detector.
- **Effect:** When set, overrides the bundled rules location; if no rules can be found the scan errors advising to set this var or install bundled rules. Empty/whitespace = use bundled default. (Note: mcp_server/server.py reads the same var with its own default /usr/share/yara/rules/.)

### `AGENTROPIX_YARA_TOOL`
- **Default:** `"yara" (DEFAULT_TOOL_NAME)`
- **Purpose:** Name or path of the YARA executable resolved via shutil.which (some distros name it differently).
- **Effect:** Override to point at a specific yara binary (e.g. yara64, full path, or a wrapper). If not found on PATH the wrapper raises FileNotFoundError with install guidance. Locates the scanner; no precision tradeoff.

## Other  (21)

### `AGENTROPIX_ARTIFACT_EXTRACT`
- **Default:** `1 (enabled) — accepts 1/true/yes/on`
- **Purpose:** On/off switch for the ArtifactAgent actually extracting artifact file contents (vs. metadata-only).
- **Effect:** On (1/true/yes/on) enables content extraction = deeper evidence and better recall but more I/O and time. Off skips extraction = faster, lighter, but misses content-level findings. Truthy default means extraction is ON.

### `AGENTROPIX_AUDIT_LOG`
- **Default:** `unset/empty (no external audit log source)`
- **Purpose:** Path to the Thymus on-disk JSONL audit log that the courtroom sealing step drains, seals into '<stem>.audit-log.json', and cross-binds into the final report seal (HMAC-SHA256 chain-of-custody).
- **Effect:** On (set to a path): the audit log is read and sealed alongside the report, giving a tamper-evident record of tool calls (stronger forensic/courtroom provenance); off (unset/empty after strip): audit_source is None and read_audit_log_jsonl is called with None, so no external audit log is sealed in. Plain string path, no clamping.

### `AGENTROPIX_CONFIG`
- **Default:** `unset/empty (skipped; falls back to /etc then ~/.config then built-in _DEFAULTS)`
- **Purpose:** Path to a JSON config file placed FIRST in the config search order, ahead of /etc/agentropix-sift/config.json and ~/.config/agentropix-sift/config.json. Its contents are deep-merged over the built-in defaults (thymus_policy, tools, monitoring).
- **Effect:** Set to load a specific config file (overrides Thymus allowed/forbidden paths, tool timeouts, rate/mem limits, etc.); unset/empty yields Path('') which is_file()==False, so it is skipped and the next search path (or pure defaults) is used. Plain string path, no clamping. Invalid JSON logs a warning and falls through.

### `AGENTROPIX_EWF_LIFECYCLE_SUDO`
- **Default:** `1 (sudo prefix enabled; read with default "1")`
- **Purpose:** Controls whether mount/unmount commands are prefixed with sudo.
- **Effect:** 0/false drops the sudo prefix (for already-privileged or rootless setups); any other value keeps sudo. Wrong setting causes permission failures.

### `AGENTROPIX_EWF_TMPDIR`
- **Default:** `unset (None — system default temp dir)`
- **Purpose:** Directory in which the temporary EWF FUSE mount-point (agentropix-sift-ewf-XXXX) is created via tempfile.mkdtemp(dir=...).
- **Effect:** Set to relocate the EWF mount scratch dir (e.g. onto a roomier or faster filesystem, or off a noexec/nosuid /tmp); unset/empty passes dir=None so the system default temp dir is used. No recall tradeoff; affects where transient mount state lands. Empty string is treated as unset.

### `AGENTROPIX_FS_SUSPICIOUS_FILENAMES`
- **Default:** `built-in set: {mimikatz, psexec, cobalt, beacon, meterpreter, nc.exe, ncat.exe, wce.exe, procdump.exe}`
- **Purpose:** Comma-separated inline list of suspicious filename literal tokens used to flag malicious files on disk (substring, case-insensitive). Fallback source when no AGENTROPIX_SUSPICIOUS_FILES_FILE is set.
- **Effect:** Setting it REPLACES the built-in default literal set (it does not merge). Add terms to widen detection (better recall, risk of false positives on benign names); a narrow set misses tooling. This inline path supports literals only — no regex (use the *_FILE form for regex). Built-in default if unset.

### `AGENTROPIX_IFEO_SKEW_TOLERANCE_SEC`
- **Default:** `0 seconds`
- **Purpose:** Extra slack (seconds) added to the correlation window upper bound to absorb clock skew between the registry-write timestamp source and the execution timestamp source.
- **Effect:** Raising tolerates more inter-source clock drift (improves pairing recall when timestamps disagree) at slight precision cost; 0 (default) demands the exec land exactly within the base window. Clamped floor 0, ceiling 5 (deliberately tight).

### `AGENTROPIX_LOG_LEVEL`
- **Default:** `WARNING`
- **Purpose:** Sets the package-wide Python logging level at import time (value is upper-cased and used as the logging level name).
- **Effect:** Lowering the level (e.g. DEBUG/INFO) produces more verbose diagnostic logging (useful for troubleshooting forensic runs, but noisier and slightly slower). Raising it (ERROR/CRITICAL) quiets logs. No effect on detection results — observability knob only.

### `AGENTROPIX_MCP_ACCESS_LOG`
- **Default:** `"" (unset → off; only 'verbose' enables it)`
- **Purpose:** Opt-in verbose HTTP access logging for the MCP server (SIFT-W-298).
- **Effect:** Set to 'verbose' to additionally log client_ip (X-Forwarded-For aware), MCP session_id, per-request request_id (echoed as X-Request-Id), user_agent, and req/resp byte sizes. Bearer token is never logged (only sha256[:16] token_hash). Default OFF keeps the audit JSON shape byte-for-byte unchanged. Any value other than 'verbose' (case-insensitive) = off.

### `AGENTROPIX_MEMORY_SUSPICIOUS_PROCS`
- **Default:** `built-in set: {mimikatz, psexec, cobaltstrike, beacon, meterpreter, lazagne, rubeus, bloodhound, sharphound}`
- **Purpose:** Comma-separated inline list of suspicious process-name literal tokens used to flag malicious processes in memory analysis (substring, case-insensitive). Fallback when no AGENTROPIX_SUSPICIOUS_PROCS_FILE is set.
- **Effect:** Setting it REPLACES the built-in default proc set (no merge). Broaden to catch more attacker tooling (more recall, more false positives); narrow to reduce noise but risk misses. Literals only — no regex support on this inline path. Built-in default if unset.

### `AGENTROPIX_PLASO_EXCLUDE_FAMILIES`
- **Default:** `"" (empty — exclude nothing)`
- **Purpose:** Comma-separated list of plaso parser families to subtract from the resolved AGENTROPIX_TIMELINE_PARSERS set (M8.4c), e.g. 'filestat,userassist'. Applied after parser resolution.
- **Effect:** Adding families prunes noisy/expensive parsers (faster, smaller plaso storage) at the cost of losing that family's events (recall). Guarded: if the exclusion would leave zero parsers it is ignored (warns) and the resolved set is kept. Empty string = no exclusions.

### `AGENTROPIX_PLASO_TAIL_PAD`
- **Default:** `off (empty/unset; truthy only for '1','true','yes')`
- **Purpose:** Boolean opt-in flag enabling a fallback 'tail padding' code path (a workaround that sidesteps a plaso edge-case described in the surrounding comment).
- **Effect:** On (=1): activates the tail-pad fallback workaround. Off (default): uses the normal path. Operational workaround toggle, not a recall/precision knob; enable only when the documented plaso edge-case is hit.

### `AGENTROPIX_RECMD_BATCH`
- **Default:** `Kroll_Batch.reb (DEFAULT_BATCH)`
- **Purpose:** Default RECmd batch (.reb) file to run when the caller does not specify one — selects which registry-key recipe set is applied.
- **Effect:** Change to run a different batch recipe (e.g. a custom .reb) by default. Resolved relative to AGENTROPIX_RECMD_BATCH_DIR (or as an absolute path). Determines which registry artifacts get extracted => affects detection coverage.

### `AGENTROPIX_RUN_ID`
- **Default:** `unset → None`
- **Purpose:** Identifier of the current analysis run, passed into the evidence-gate token verify+spend (verify_and_spend) so spent capability tokens are scoped/attributed to a run. Read only on the Step-2 (non-stub) atomic verify+spend path.
- **Effect:** Set per-run to bind evidence-gate token spends to that run id (auditability / scoping of token consumption); leave unset and run_id is None (tokens spent without run scoping). Read verbatim from the env, no clamping.

### `AGENTROPIX_STATUS_TAXONOMY`
- **Default:** `off (unset/empty)`
- **Purpose:** Feature gate that opts wrapper output into the new structured status-taxonomy fields (rolled out behind a flag for one release). Truthy for '1','true','yes'.
- **Effect:** On: wrappers emit the new status-taxonomy fields (richer/normalized status reporting for downstream consumers). Off (default): legacy status shape is used. Behavioral/format toggle for staged rollout; no recall/precision impact.

### `AGENTROPIX_VOL_TCPIP_SYMBOLS_OK`
- **Default:** `"0" (off)`
- **Purpose:** W-075 operator assertion that the tcpip.sys symbol pack is locally available, second gate for enabling the netstat plugin in should_use_netstat().
- **Effect:** Off (default) keeps netstat disabled even if AGENTROPIX_VOL_USE_NETSTAT=1. On (1/true/yes/on) AND netstat enabled => netstat is used. Asserting this falsely makes netstat run against missing symbols and return empty results (recall loss / blind spot on network connections). Leave off unless you have pre-fetched the symbols.

### `AGENTROPIX_XXD_COLS`
- **Default:** `16`
- **Purpose:** Bytes per output line in the hex dump (xxd -c).
- **Effect:** Raise for wider rows (fewer, longer lines); lower for narrower rows. Cosmetic/readability of the dump only; does not change which bytes are read. Clamped floor 1, ceiling 256.

### `AGENTROPIX_XXD_GROUP`
- **Default:** `1`
- **Purpose:** Byte grouping/octet width in the hex column (xxd -g).
- **Effect:** Raise to group more bytes per hex cluster; lower (1) for byte-by-byte. Display formatting only. Clamped floor 1, ceiling 16.

### `AGENTROPIX_XXD_LENGTH`
- **Default:** `256`
- **Purpose:** Number of bytes to dump from the start offset (xxd -l); also the byte count re-read for the region SHA-256.
- **Effect:** Raise to view/hash a larger region; lower for a tighter window. Recall-vs-payload-size: ceiling 65536 caps one call so it can't dump an entire image. Clamped floor 1, ceiling 65536.

### `AGENTROPIX_XXD_OFFSET`
- **Default:** `0`
- **Purpose:** Start byte offset for the dump (xxd -s) and the seek position for the integrity re-read.
- **Effect:** Raise to begin the dump deeper into the file; 0 starts at the beginning. Negative is rejected (ValueError). Selects which region is shown/hashed; no speed tradeoff. Clamped floor 0, ceiling 2**40.

### `AGENTROPIX_YARA_MOUNT_PREFIX`
- **Default:** `"" (unset — empty string; E01 scans skipped when absent)`
- **Purpose:** Filesystem path to the mounted root of an E01/disk image so YARA can scan the mounted contents instead of the raw image.
- **Effect:** If unset when scanning an E01 image, YARA is skipped (logged 'skipping YARA') since raw EWF cannot be scanned directly; set it to the mounted root to enable scanning. String, .strip()'d; empty = unset.
