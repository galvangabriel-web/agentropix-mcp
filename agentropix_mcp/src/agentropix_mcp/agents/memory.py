"""MemoryAgent — volatile-evidence specialist.

Calls Volatility (mcp_get_pslist) on memory images. Flags suspicious
process names and orphan processes (PPID with no live parent). Skips
itself on disk-only images so the swarm can run uniformly.

Pre-flight (W-074): ``windows.info`` is consulted before pslist so a
paused-VM snapshot (``KeNumberProcessors=0``) gets a low-confidence
informational Finding describing the dump quality. The structural
fallback from pslist→psscan (already in :mod:`mcp_server.wrappers.volatility`)
recovers the process tree; the new Finding ensures analysts who read
the report know the dump quality flag was set.

Credential triage (W-072 / ADR-014): when ``AGENTROPIX_IMPACKET_ENABLED=1``
and a SAM/SECURITY/SYSTEM hive triple is reachable under
``AGENTROPIX_HIVE_DIR`` (operator stages it there per
docs/operator/W-072-HIVE-FIXTURE-EXTRACTION.md), the agent shells to
``impacket-secretsdump.py LOCAL`` and emits one Finding per recovered
NTLM hash / LSA secret / cached domain credential. When the gate is
off (env unset, binary missing, hives absent) a single low-confidence
``memory.credentials.unavailable`` Finding records why no credential
material was recovered so report consumers don't see a silent gap.
"""

from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path

from agentropix_mcp.agents._base import Finding, SwarmAgent
from agentropix_mcp.agents._evidence import looks_like_memory
from agentropix_mcp.agents._suspicious import get_proc_matchers, matches_name
from agentropix_mcp._env import get_float, get_int_set
from agentropix_mcp.server import ToolError, mcp_get_pslist
from agentropix_mcp.wrappers.correlation import build_process_tree
from agentropix_mcp.wrappers.credentials import (
    DEFAULT_TOOLS as _SECRETSDUMP_DEFAULT_TOOLS,
)
from agentropix_mcp.wrappers.credentials import (
    CredentialDumpReport,
    secretsdump_local,
)
from agentropix_mcp.wrappers.volatility import (
    _CACHEDUMP_HASH_PREVIEW_CHARS,
    _CMDSCAN_LINE_PREVIEW_CHARS,
    _CONSOLES_BUFFER_PREVIEW_CHARS,
    _LSADUMP_VALUE_PREVIEW_CHARS,
    CachedumpReport,
    CmdscanReport,
    ConsolesReport,
    HashdumpReport,
    LsadumpReport,
    MalfindReport,
    MemoryInfo,
    NetscanReport,
    RegistryPersistenceReport,
    SvcscanReport,
    get_cachedump,
    get_cmdscan,
    get_consoles,
    get_hashdump,
    get_info,
    get_lsadump,
    get_malfind,
    get_netscan,
    get_registry_run_keys,
    get_svcscan,
    get_userassist,
    is_service_binary_outside_system32,
    is_snapshot_paused,
)

logger = logging.getLogger(__name__)

_DEFAULT_KERNEL_PPIDS: set[int] = {0, 4}


async def _safe_get_info(image: Path) -> MemoryInfo | None:
    """W-074 pre-flight wrapper. Never raises — pre-flight failure must
    not stop MemoryAgent from running its main investigation. Returns
    ``None`` when the helper cannot probe the dump at all (caller treats
    that as "quality unknown")."""
    try:
        return await get_info(image)
    except (FileNotFoundError, RuntimeError, TimeoutError, MemoryError) as exc:
        logger.warning("windows.info pre-flight failed: %s", exc)
        return None


async def _safe_call(coro_factory, label: str):
    """W-071: each native vol3 wrapper is best-effort — a single plugin
    failure (missing symbols, paused-VM corner case, RAM cap) must not
    abort the whole MemoryAgent investigation. Returns ``None`` on any
    raise so the caller can keep collecting findings from the others.
    """
    try:
        return await coro_factory()
    except (FileNotFoundError, RuntimeError, TimeoutError, MemoryError) as exc:
        logger.warning("vol3 plugin %s failed: %s", label, exc)
        return None


def _is_rfc1918(addr: str) -> bool:
    """Quick filter for RFC1918 private space — sockets to public IPs
    are higher-signal IOCs than chatter to a domain controller on the
    same /16. The check is a string prefix match because the addresses
    arrive pre-stringified from vol3."""
    if not addr:
        return False
    if addr.startswith("10."):
        return True
    if addr.startswith("192.168."):
        return True
    if addr.startswith("172."):
        try:
            second = int(addr.split(".")[1])
        except (ValueError, IndexError):
            return False
        return 16 <= second <= 31
    if addr.startswith(("127.", "::1", "fe80:")):
        return True
    return False


def _findings_from_malfind(report: MalfindReport, image: Path) -> list[Finding]:
    out: list[Finding] = []
    for hit in report.hits:
        out.append(
            Finding(
                source="memory.injection",
                confidence=0.85,
                description=f"malfind hit: {hit.process} (pid={hit.pid}) {hit.protection}",
                evidence=(
                    f"pid={hit.pid} process={hit.process} address={hit.address} "
                    f"vad_tag={hit.vad_tag} protection={hit.protection}"
                ),
                evidence_dict={
                    "pid": hit.pid,
                    "process": hit.process,
                    "address": hit.address,
                    "vad_tag": hit.vad_tag,
                    "protection": hit.protection,
                    "private_memory": hit.private_memory,
                    "hexdump_head": hit.hexdump_head,
                    "image": str(image),
                },
                mitre_attack="T1055",
                timestamp=Finding.now(),
            )
        )
        # Issue #11: when get_malfind successfully chained vaddump for
        # this hit, emit a second Finding carrying the SHA-256 of the
        # dumped bytes plus a sample of printable strings. The flag
        # Finding above always emits regardless — the payload Finding is
        # additive and silently skipped when the dump failed (cap reached,
        # subprocess error, oversize VAD).
        if hit.payload_sha256:
            sample = hit.payload_strings[:5]
            out.append(
                Finding(
                    source="memory.injection.payload",
                    confidence=0.9,
                    description=(
                        f"malfind payload: {hit.process} (pid={hit.pid}) "
                        f"{hit.payload_bytes} bytes sha256={hit.payload_sha256[:12]}..."
                    ),
                    evidence=(
                        f"pid={hit.pid} addr={hit.address} bytes={hit.payload_bytes} "
                        f"sha256={hit.payload_sha256} strings_sample={sample}"
                    ),
                    evidence_dict={
                        "pid": hit.pid,
                        "process": hit.process,
                        "address": hit.address,
                        "payload_bytes": hit.payload_bytes,
                        "strings_sample": sample,
                        "strings_total": len(hit.payload_strings),
                        "image": str(image),
                    },
                    mitre_attack="T1055",
                    file_sha256=hit.payload_sha256,
                    timestamp=Finding.now(),
                )
            )
    return out


def _findings_from_process_tree(report, image: Path) -> list[Finding]:
    """Extract findings from process-tree analysis (orphans + suspicious parents)."""
    out: list[Finding] = []
    # Flag orphan processes (parent gone — DKOM or normal termination)
    for node in report.orphans:
        out.append(
            Finding(
                source="memory.process_tree",
                confidence=0.75,
                description=f"Orphan process: {node.name} (pid={node.pid}, ppid={node.ppid})",
                evidence=(
                    f"pid={node.pid} ppid={node.ppid} name={node.name} "
                    f"threads={node.threads} wow64={node.wow64}"
                ),
                mitre_attack="T1564.012",
                timestamp=Finding.now(),
            )
        )
    # Flag suspicious processes (LOLBin from sensitive parent)
    for node in report.roots:
        def check_suspicious_recursive(n, depth=0):
            findings = []
            if n.suspicious:
                findings.append(
                    Finding(
                        source="memory.process_tree",
                        confidence=0.8,
                        description=(
                            f"Suspicious parent-child: {n.suspicious_reason} "
                            f"(pid={n.pid} {n.name})"
                        ),
                        evidence=f"pid={n.pid} ppid={n.ppid} name={n.name} reason={n.suspicious_reason}",
                        mitre_attack="T1218",
                        timestamp=Finding.now(),
                    )
                )
            for child in n.children:
                findings.extend(check_suspicious_recursive(child, depth + 1))
            return findings
        out.extend(check_suspicious_recursive(node))
    return out


def _findings_from_netscan(report: NetscanReport, image: Path) -> list[Finding]:
    out: list[Finding] = []
    for sock in report.sockets:
        # IOC-promote established sockets to public (non-RFC1918) addresses.
        # All sockets still emit findings, but the public-address ones get
        # higher confidence so the cohit≥2 scorer credits them.
        public = bool(sock.foreign_addr) and not _is_rfc1918(sock.foreign_addr)
        established = sock.state.upper() == "ESTABLISHED"
        confidence = 0.7 if (public and established) else 0.4
        out.append(
            Finding(
                source="memory.socket",
                confidence=confidence,
                description=(
                    f"{sock.proto} {sock.local_addr}:{sock.local_port} ↔ "
                    f"{sock.foreign_addr}:{sock.foreign_port} ({sock.state or 'no-state'})"
                ),
                evidence=(
                    f"proto={sock.proto} local={sock.local_addr}:{sock.local_port} "
                    f"foreign={sock.foreign_addr}:{sock.foreign_port} "
                    f"state={sock.state} pid={sock.pid} owner={sock.owner}"
                ),
                evidence_dict={
                    "proto": sock.proto,
                    "local_addr": sock.local_addr,
                    "local_port": sock.local_port,
                    "foreign_addr": sock.foreign_addr,
                    "foreign_port": sock.foreign_port,
                    "state": sock.state,
                    "pid": sock.pid,
                    "owner": sock.owner,
                    "ip_class": "public" if public else "private",
                    "image": str(image),
                },
                timestamp=Finding.now(),
            )
        )
    return out


def _findings_from_svcscan(report: SvcscanReport, image: Path) -> list[Finding]:
    out: list[Finding] = []
    for svc in report.services:
        outside = is_service_binary_outside_system32(svc)
        confidence = 0.75 if outside else 0.3
        out.append(
            Finding(
                source="memory.service",
                confidence=confidence,
                description=(
                    f"Service: {svc.name} ({svc.display}) — "
                    f"binary={svc.binary or '(empty)'}"
                ),
                evidence=(
                    f"name={svc.name} state={svc.state} start={svc.start} "
                    f"binary={svc.binary} dll={svc.dll}"
                ),
                evidence_dict={
                    "name": svc.name,
                    "display": svc.display,
                    "state": svc.state,
                    "start": svc.start,
                    "type": svc.type,
                    "binary": svc.binary,
                    "dll": svc.dll,
                    "pid": svc.pid,
                    "binary_outside_system32": outside,
                    "image": str(image),
                },
                # T1543.003 — Create or Modify System Process: Windows Service.
                # Only tagged when the binary is non-standard; otherwise the
                # row is benign baseline.
                mitre_attack="T1543.003" if outside else "",
                timestamp=Finding.now(),
            )
        )
    return out


def _findings_from_hashdump(report: HashdumpReport, image: Path) -> list[Finding]:
    """Issue #12 — emit one Finding per ``windows.hashdump`` row (T1003.002).

    Each Finding tags ``T1003.002`` (OS Credential Dumping: SAM) and carries
    user / RID / LM hash / NT hash in evidence_dict so the cohit≥2 scorer
    can correlate against disk-side T1003.002 evidence (e.g. SAM hive copy).
    NTLM hash strings are kept whole — partial truncation would break the
    downstream pass-the-hash IOC pivot.
    """
    out: list[Finding] = []
    for entry in report.entries:
        nt_short = entry.nt_hash[:12] if entry.nt_hash else ""
        out.append(
            Finding(
                source="memory.credential.hashdump",
                confidence=0.9,
                description=f"SAM NTLM hash recovered: {entry.user} (rid={entry.rid})",
                evidence=(
                    f"user={entry.user} rid={entry.rid} "
                    f"lm={entry.lm_hash} nt={nt_short}..."
                ),
                evidence_dict={
                    "user": entry.user,
                    "rid": entry.rid,
                    "lm_hash": entry.lm_hash,
                    "nt_hash": entry.nt_hash,
                    "row": entry.row,
                    "image": str(image),
                },
                mitre_attack="T1003.002",
                timestamp=Finding.now(),
            )
        )
    return out


def _findings_from_lsadump(report: LsadumpReport, image: Path) -> list[Finding]:
    """Issue #12 — emit one Finding per ``windows.lsadump`` row (T1003.004).

    Per the issue-12 hardening rule, the structured ``evidence_dict`` carries
    only metadata (name, hex length, image) — the full secret/value blob is
    never serialised into the wire-format report. The truncated value preview
    (``_LSADUMP_VALUE_PREVIEW_CHARS``) lives only in the human-readable
    ``evidence`` string so an analyst can spot well-known secret prefixes
    without dumping the whole hash into a report sent over the MCP wire.
    """
    out: list[Finding] = []
    for entry in report.entries:
        out.append(
            Finding(
                source="memory.credential.lsadump",
                confidence=0.9,
                description=f"LSA secret recovered: {entry.name}",
                evidence=(
                    f"name={entry.name} "
                    f"value_preview={entry.value[:_LSADUMP_VALUE_PREVIEW_CHARS]}"
                ),
                evidence_dict={
                    "name": entry.name,
                    "value_hex_len": len(entry.value_hex),
                    "image": str(image),
                },
                mitre_attack="T1003.004",
                timestamp=Finding.now(),
            )
        )
    return out


def _findings_from_cachedump(
    report: CachedumpReport, image: Path
) -> list[Finding]:
    """Issue #12 — emit one Finding per ``windows.cachedump`` row (T1003.005).

    MSCache (DCC2) hashes are credential material; ``evidence_dict`` carries
    only metadata (user, domain, mscache_hash_len, image) so the structured
    wire-format report never serialises the full cached hash. The
    human-readable ``evidence`` string surfaces a truncated preview
    (``_CACHEDUMP_HASH_PREVIEW_CHARS``) so an analyst can spot
    ``$DCC2$`` prefix conventions without dumping the whole hash.
    """
    out: list[Finding] = []
    for entry in report.entries:
        hash_preview = entry.mscache_hash[:_CACHEDUMP_HASH_PREVIEW_CHARS]
        out.append(
            Finding(
                source="memory.credential.cachedump",
                confidence=0.9,
                description=(
                    f"Cached domain credential recovered: "
                    f"{entry.user}@{entry.domain or '?'}"
                ),
                evidence=(
                    f"user={entry.user} domain={entry.domain} "
                    f"mscache_hash={hash_preview}"
                ),
                evidence_dict={
                    "user": entry.user,
                    "domain": entry.domain,
                    "mscache_hash_len": len(entry.mscache_hash),
                    "image": str(image),
                },
                mitre_attack="T1003.005",
                timestamp=Finding.now(),
            )
        )
    return out


def _findings_from_cmdscan(
    report: CmdscanReport, image: Path
) -> list[Finding]:
    """Issue #12 — emit one Finding per ``windows.cmdscan`` row (T1059.003).

    Recovered console command lines can carry credentials, encoded
    payloads, or operator pipelines; ``evidence_dict`` carries only
    metadata (pid, process, command_line_len, image) so the structured
    wire-format report never serialises the full command line. The
    human-readable ``evidence`` string surfaces a truncated preview
    (``_CMDSCAN_LINE_PREVIEW_CHARS``) so an analyst can spot the
    invocation without flooding the report with very long lines.
    """
    out: list[Finding] = []
    for entry in report.entries:
        line_preview = entry.command_line[:_CMDSCAN_LINE_PREVIEW_CHARS]
        out.append(
            Finding(
                source="memory.credential.cmdscan",
                confidence=0.85,
                description=(
                    f"Console command recovered: pid={entry.pid} "
                    f"process={entry.process or '?'}"
                ),
                evidence=(
                    f"pid={entry.pid} process={entry.process} "
                    f"command_line={line_preview}"
                ),
                evidence_dict={
                    "pid": entry.pid,
                    "process": entry.process,
                    "command_line_len": len(entry.command_line),
                    "image": str(image),
                },
                mitre_attack="T1059.003",
                timestamp=Finding.now(),
            )
        )
    return out


def _findings_from_consoles(
    report: ConsolesReport, image: Path
) -> list[Finding]:
    """Issue #12 — emit one Finding per ``windows.consoles`` row (T1059.003).

    Recovered console buffers are typically multi-line and can carry
    credentials, encoded payloads, or operator output; ``evidence_dict``
    carries only metadata (pid, process, console_buffer_len, image) so
    the structured wire-format report never serialises the full buffer.
    The human-readable ``evidence`` string surfaces a truncated preview
    (``_CONSOLES_BUFFER_PREVIEW_CHARS``) wider than cmdscan's because
    the buffer captures useful surrounding context.
    """
    out: list[Finding] = []
    for entry in report.entries:
        buffer_preview = entry.console_buffer[:_CONSOLES_BUFFER_PREVIEW_CHARS]
        out.append(
            Finding(
                source="memory.credential.consoles",
                confidence=0.85,
                description=(
                    f"Console buffer recovered: pid={entry.pid} "
                    f"process={entry.process or '?'}"
                ),
                evidence=(
                    f"pid={entry.pid} process={entry.process} "
                    f"console_buffer={buffer_preview}"
                ),
                evidence_dict={
                    "pid": entry.pid,
                    "process": entry.process,
                    "console_buffer_len": len(entry.console_buffer),
                    "image": str(image),
                },
                mitre_attack="T1059.003",
                timestamp=Finding.now(),
            )
        )
    return out


def _findings_from_registry(
    report: RegistryPersistenceReport, image: Path
) -> list[Finding]:
    out: list[Finding] = []
    for entry in report.entries:
        out.append(
            Finding(
                source="memory.persistence.registry",
                confidence=0.6,
                description=(
                    f"Registry persistence ({entry.source_plugin}): "
                    f"{entry.key}\\{entry.value}"
                ),
                evidence=(
                    f"hive={entry.hive} key={entry.key} value={entry.value} "
                    f"data={entry.data}"
                ),
                evidence_dict={
                    "hive": entry.hive,
                    "registry_key": entry.key,
                    "registry_value": entry.value,
                    "data": entry.data,
                    "last_write": entry.last_write,
                    "source_plugin": entry.source_plugin,
                    "image": str(image),
                },
                mitre_attack="T1547.001",
                timestamp=Finding.now(),
            )
        )
    return out


class MemoryAgent(SwarmAgent):
    name = "memory"
    completion_promise = "MEMORY_TRIAGED"  # M8.3d: emitted when ≥1 Finding lands

    async def investigate(self, image: Path) -> list[Finding]:
        if not looks_like_memory(image):
            # W-105: emit a single info-level skip Finding instead of the
            # bare ``return []``. Three reasons:
            #   1. Critic.plan_gaps no longer treats memory as an unfilled
            #      plan slot, so the Architect doesn't re-plan a known-
            #      no-op agent for iterations 2..N (was burning ~75% of
            #      the per-run budget on a re-plan loop).
            #   2. Operators reading the report see a clear "why no
            #      memory analysis" reason instead of a silent gap.
            #   3. The cross-reference to the W-067 AppData detector in
            #      TimelineAgent points future investigators at the
            #      disk-mode path that actually covers T1055 here.
            # The completion_promise (MEMORY_TRIAGED) is cleared so the
            # orchestrator does NOT add it to ``report.completion_proofs``
            # — the skip Finding is informational, not a triage proof.
            self.completion_promise = ""
            return [
                Finding(
                    source="memory.skip",
                    confidence=0.0,
                    description=(
                        "MemoryAgent skipped: image is not a memory dump "
                        "(disk-only). Volatility plugins require RAM "
                        "capture; T1055 disk-side coverage is provided "
                        "by the AppData-staging detector in TimelineAgent "
                        "(W-067)."
                    ),
                    evidence=f"image={image} suffix={image.suffix}",
                    timestamp=Finding.now(),
                )
            ]

        proc_literals, proc_patterns = get_proc_matchers()
        kernel_ppids = get_int_set(
            "AGENTROPIX_MEMORY_KERNEL_PPIDS",
            _DEFAULT_KERNEL_PPIDS,
        )
        suspicious_conf = get_float(
            "AGENTROPIX_MEMORY_SUSPICIOUS_CONFIDENCE",
            0.85,
            floor=0.0,
            ceiling=1.0,
        )
        orphan_conf = get_float(
            "AGENTROPIX_MEMORY_ORPHAN_CONFIDENCE",
            0.55,
            floor=0.0,
            ceiling=1.0,
        )

        findings: list[Finding] = []

        # W-074 pre-flight: detect paused-VM snapshots and tag the dump
        # quality so analysts don't read empty pslist as "no live malware."
        info = await _safe_get_info(image)
        if info is not None and is_snapshot_paused(info):
            findings.append(
                Finding(
                    source="memory.info",
                    confidence=0.4,
                    description=(
                        "Memory dump is a paused-VM snapshot "
                        "(KeNumberProcessors=0). Pool-scan plugins "
                        "(psscan/netscan/etc.) used in lieu of list-walking."
                    ),
                    evidence=f"image={image} ke_number_processors=0",
                    evidence_dict={
                        "image": str(image),
                        "quality": "snapshot_paused",
                        "ke_number_processors": 0,
                    },
                    timestamp=Finding.now(),
                )
            )

        result = await mcp_get_pslist(str(image))
        if isinstance(result, ToolError):
            findings.append(
                Finding(
                    source="memory.pslist",
                    confidence=0.0,
                    description=f"pslist failed: {result.error}",
                    evidence=f"image={image}",
                )
            )
            return findings

        live_pids = {p.pid for p in result.processes}

        for proc in result.processes:
            name_lower = proc.name.lower()
            if matches_name(name_lower, proc_literals, proc_patterns):
                findings.append(
                    Finding(
                        source="memory.pslist",
                        confidence=suspicious_conf,
                        description=f"Suspicious process: {proc.name}",
                        evidence=f"pid={proc.pid} ppid={proc.ppid} name={proc.name}",
                        timestamp=Finding.now(),
                        mitre_attack="T1003" if "mimikatz" in name_lower else "T1059",
                    )
                )
            elif proc.ppid not in live_pids and proc.ppid not in kernel_ppids:
                findings.append(
                    Finding(
                        source="memory.pslist",
                        confidence=orphan_conf,
                        description=f"Orphan process (parent gone): {proc.name}",
                        evidence=f"pid={proc.pid} ppid={proc.ppid}",
                        timestamp=Finding.now(),
                    )
                )

        # W-A05: Wire build_process_tree into per-host pipeline for full PPID
        # forest + orphan detection (DKOM indicator) + suspicious parent flags
        if result.process_count > 1:
            try:
                tree_report = await build_process_tree(image, timeout=120)
                findings.extend(_findings_from_process_tree(tree_report, image))
            except (FileNotFoundError, RuntimeError, TimeoutError) as exc:
                logger.warning("build_process_tree failed for %s: %s", image, exc)

        # W-071 — native vol3 wrappers around malfind (T1055), netscan
        # (W-075 default), svcscan (T1543.003), and registry persistence
        # (T1547.001 via printkey + userassist). Each wrapper is best-
        # effort: a single plugin failure must not abort the agent.
        malfind_report = await _safe_call(lambda: get_malfind(image), "malfind")
        if malfind_report is not None:
            findings.extend(_findings_from_malfind(malfind_report, image))

        netscan_report = await _safe_call(lambda: get_netscan(image), "netscan")
        if netscan_report is not None:
            findings.extend(_findings_from_netscan(netscan_report, image))

        svcscan_report = await _safe_call(lambda: get_svcscan(image), "svcscan")
        if svcscan_report is not None:
            findings.extend(_findings_from_svcscan(svcscan_report, image))

        run_keys = await _safe_call(
            lambda: get_registry_run_keys(image), "registry-run-keys"
        )
        if run_keys is not None:
            findings.extend(_findings_from_registry(run_keys, image))

        userassist = await _safe_call(lambda: get_userassist(image), "userassist")
        if userassist is not None:
            findings.extend(_findings_from_registry(userassist, image))

        # Issue #12 — credential-dump plugins. Each is best-effort via
        # _safe_call so a single plugin failure (missing symbols, locked
        # SAM hive, paused-VM snapshot) doesn't abort the rest of the
        # credential-domain coverage.
        hashdump_report = await _safe_call(lambda: get_hashdump(image), "hashdump")
        if hashdump_report is not None:
            findings.extend(_findings_from_hashdump(hashdump_report, image))

        lsadump_report = await _safe_call(lambda: get_lsadump(image), "lsadump")
        if lsadump_report is not None:
            findings.extend(_findings_from_lsadump(lsadump_report, image))

        cachedump_report = await _safe_call(lambda: get_cachedump(image), "cachedump")
        if cachedump_report is not None:
            findings.extend(_findings_from_cachedump(cachedump_report, image))

        consoles_report = await _safe_call(lambda: get_consoles(image), "consoles")
        if consoles_report is not None:
            findings.extend(_findings_from_consoles(consoles_report, image))

        cmdscan_report = await _safe_call(lambda: get_cmdscan(image), "cmdscan")
        if cmdscan_report is not None:
            findings.extend(_findings_from_cmdscan(cmdscan_report, image))

        # W-072 / ADR-014 — credential triage via impacket-secretsdump
        # against a previously extracted SAM/SECURITY/SYSTEM hive triple.
        # Always emits at least one Finding (either populated rows or a
        # single ``memory.credentials.unavailable`` row explaining why)
        # so credential coverage is never a silent gap.
        findings.extend(await _credential_triage_findings(image))

        return findings


def _credentials_unavailable(reason: str, image: Path) -> Finding:
    """Single low-confidence Finding for the disabled / missing-dependency path.

    The credential domain is load-bearing for an APT investigation
    (T1003.* OS Credential Dumping); a silent skip would let an
    analyst think no credential material existed when in reality the
    triage path simply wasn't run. The Finding tags the canonical
    sub-technique (T1003.002 SAM) so the report's MITRE coverage view
    flags the gap rather than pretending the technique was checked
    and cleared.
    """
    return Finding(
        source="memory.credentials.unavailable",
        confidence=0.1,
        description=f"Credential triage skipped: {reason}",
        evidence=f"image={image}",
        evidence_dict={
            "image": str(image),
            "reason": reason,
            "tool": "impacket-secretsdump",
        },
        mitre_attack="T1003.002",
        timestamp=Finding.now(),
    )


def _resolve_hive_triple() -> tuple[Path, Path, Path] | None:
    """Locate the SAM/SECURITY/SYSTEM triple staged by the operator.

    The agent does not extract hives itself — that requires escalated
    tooling outside the MCP boundary (see
    docs/operator/W-072-HIVE-FIXTURE-EXTRACTION.md). Instead the
    operator stages the triple under ``AGENTROPIX_HIVE_DIR`` and the
    agent consumes whatever is there. Returns ``None`` when the env
    var is unset or any of the three hive files is missing — caller
    treats that as "no hives" and emits the unavailable Finding.

    The lookup is case-insensitive on filename so a Windows-export
    capitalisation (``SAM``) and a Linux convention (``Sam``) both
    resolve to the same path.
    """
    raw = os.environ.get("AGENTROPIX_HIVE_DIR", "").strip()
    if not raw:
        return None
    base = Path(raw)
    if not base.is_dir():
        return None
    found: dict[str, Path] = {}
    for child in base.iterdir():
        if not child.is_file():
            continue
        upper = child.name.upper()
        if upper == "SAM":
            found["sam"] = child
        elif upper == "SECURITY":
            found["security"] = child
        elif upper == "SYSTEM":
            found["system"] = child
    try:
        return found["sam"], found["security"], found["system"]
    except KeyError:
        return None


def _findings_from_credentials(
    report: CredentialDumpReport, image: Path
) -> list[Finding]:
    """Emit one Finding per recovered credential row.

    Per ADR-014 the confidence is high (0.95) because impacket-secretsdump
    output is authoritative — it's the same code path attackers use
    offline. MITRE sub-techniques per row family:

    * SAM NTLM hashes  → T1003.002 (OS Credential Dumping: SAM)
    * Cached MSCache   → T1003.005 (Cached Domain Credentials)
    * LSA secrets      → T1003.001 (LSASS Memory)
    """
    out: list[Finding] = []
    for row in report.ntlm_hashes:
        short = row.ntlm_hash[:12] if row.ntlm_hash else ""
        out.append(
            Finding(
                source="memory.credentials.sam",
                confidence=0.95,
                description=f"NTLM hash extracted: {row.account}",
                evidence=(
                    f"account={row.account} rid={row.rid} hash={short}..."
                ),
                evidence_dict={
                    "account": row.account,
                    "rid": row.rid,
                    "ntlm_hash": row.ntlm_hash,
                    "lm_hash": row.lm_hash,
                    "hive": "SAM",
                    "extraction_tool": "impacket-secretsdump",
                    "image": str(image),
                },
                mitre_attack="T1003.002",
                timestamp=Finding.now(),
            )
        )
    for row in report.cached_domain_creds:
        out.append(
            Finding(
                source="memory.credentials.cached",
                confidence=0.95,
                description=f"Cached domain credential: {row.account}@{row.domain or '?'}",
                evidence=f"account={row.account} domain={row.domain}",
                evidence_dict={
                    "account": row.account,
                    "domain": row.domain,
                    "dcc2_hash": row.dcc2_hash,
                    "hive": "SECURITY",
                    "extraction_tool": "impacket-secretsdump",
                    "image": str(image),
                },
                mitre_attack="T1003.005",
                timestamp=Finding.now(),
            )
        )
    for row in report.lsa_secrets:
        out.append(
            Finding(
                source="memory.credentials.lsa",
                confidence=0.95,
                description=f"LSA secret recovered: {row.name}",
                evidence=f"name={row.name} value_len={len(row.value_hex)}",
                evidence_dict={
                    "name": row.name,
                    "value_hex": row.value_hex,
                    "hive": "SECURITY",
                    "extraction_tool": "impacket-secretsdump",
                    "image": str(image),
                },
                mitre_attack="T1003.001",
                timestamp=Finding.now(),
            )
        )
    return out


async def _credential_triage_findings(image: Path) -> list[Finding]:
    """Gate + dispatch for the W-072 credential-triage branch.

    Order of gates (each failure short-circuits with a single
    ``memory.credentials.unavailable`` Finding):

    1. ``AGENTROPIX_IMPACKET_ENABLED=1`` — opt-in env var (the impacket
       install is heavyweight and disabled by default per ADR-014).
    2. ``impacket-secretsdump.py`` (or ``secretsdump.py``) on PATH —
       so the wrapper subprocess won't fail.
    3. Hive triple under ``AGENTROPIX_HIVE_DIR`` — operator stages SAM,
       SECURITY, SYSTEM there.

    Once all three gates pass the wrapper is invoked. Wrapper failures
    (Thymus reject, timeout, runtime error) downgrade to the
    unavailable Finding rather than aborting MemoryAgent.
    """
    if os.environ.get("AGENTROPIX_IMPACKET_ENABLED", "").strip() != "1":
        return [_credentials_unavailable(
            "AGENTROPIX_IMPACKET_ENABLED!=1 (opt-in per ADR-014)",
            image,
        )]

    override = os.environ.get("AGENTROPIX_SECRETSDUMP_TOOL", "").strip()
    candidates = (override,) if override else _SECRETSDUMP_DEFAULT_TOOLS
    if not any(shutil.which(name) for name in candidates if name):
        return [_credentials_unavailable(
            "impacket-secretsdump not on PATH (install: pip install impacket)",
            image,
        )]

    triple = _resolve_hive_triple()
    if triple is None:
        return [_credentials_unavailable(
            "no SAM/SECURITY/SYSTEM hive triple under AGENTROPIX_HIVE_DIR",
            image,
        )]

    sam, security, system = triple
    try:
        report = await secretsdump_local(sam, security, system)
    except (FileNotFoundError, PermissionError, RuntimeError, TimeoutError) as exc:
        logger.warning("secretsdump_local failed: %s", exc)
        return [_credentials_unavailable(f"secretsdump call failed: {exc}", image)]

    findings = _findings_from_credentials(report, image)
    if not findings:
        warn = "; ".join(report.parse_warnings) if report.parse_warnings else (
            "secretsdump produced no credential rows"
        )
        return [_credentials_unavailable(warn, image)]
    return findings
