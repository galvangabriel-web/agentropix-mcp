"""FilesystemAgent — directory-walk specialist.

Calls Sleuth Kit (mcp_fls) on disk images. Flags deleted entries and
filenames matching a known-bad list. The W3 expansion adds NTFS ADS
detection, MFT timestomp checks, and prefetch parsing.

W-048 (M6): deleted-entry emission is gated by filename-suspicion by
default. A typical Windows C: volume walked by fls carries tens of
thousands of deleted-but-unallocated inodes (browser cache, temp
files, rotated logs) that are not forensically interesting on their
own. The legacy "emit every deleted inode" path is preserved behind
``AGENTROPIX_FS_EMIT_DELETED_ALL=1`` so forensic-curious operators can
re-enable it case-by-case; the swarm-default is "deleted + suspicious
name" which keeps tools like mimikatz surfacing even when they were
unlinked post-exploitation.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

from agentropix_mcp.agents._base import Finding, SwarmAgent
from agentropix_mcp.agents._enrichment import enriched_finding
from agentropix_mcp.agents._evidence import looks_like_disk
from agentropix_mcp.agents._suspicious import get_file_matchers, matches_name
from agentropix_mcp._env import get_float, get_int
from agentropix_mcp.server import ToolError, mcp_fls
from agentropix_mcp.wrappers.tsk import _read_inode

logger = logging.getLogger(__name__)


def _hash_inode(image: Path, inode_str: str) -> str:
    """Issue #10 — return SHA-256 hex of an inode's bytes, or "" on miss.

    Filenames flagged as suspicious by FilesystemAgent get hashed so
    operators can pivot to VirusTotal / Hybrid Analysis / threat-intel
    without re-acquiring the file. Failure modes (unparseable inode,
    pytsk3 unavailable, oversize file, dead inode) all collapse to ""
    rather than raising — a missing hash is non-fatal to the finding.
    """
    if not inode_str:
        return ""
    # fls inodes look like "1234-128-1" (NTFS) or "42" (ext); the
    # leading numeric portion is what TSK accepts via open_meta.
    head = inode_str.split("-", 1)[0]
    try:
        inode_int = int(head)
    except ValueError:
        return ""
    try:
        data = _read_inode(image, inode_int)
    except FileNotFoundError:
        return ""
    except Exception as exc:  # noqa: BLE001 — defensive: hashing must not fail the agent
        logger.warning("inode %s hash failed for %s: %s", inode_str, image, exc)
        return ""
    if not data:
        return ""
    return hashlib.sha256(data).hexdigest()


class FilesystemAgent(SwarmAgent):
    name = "filesystem"
    completion_promise = "FILESYSTEM_WALKED"  # M8.3d

    async def investigate(self, image: Path) -> list[Finding]:
        if not looks_like_disk(image):
            return []

        file_literals, file_patterns = get_file_matchers()
        deleted_conf = get_float(
            "AGENTROPIX_FS_DELETED_CONFIDENCE",
            0.6,
            floor=0.0,
            ceiling=1.0,
        )
        suspicious_conf = get_float(
            "AGENTROPIX_FS_SUSPICIOUS_CONFIDENCE",
            0.85,
            floor=0.0,
            ceiling=1.0,
        )
        fls_recursive = bool(
            get_int(
                "AGENTROPIX_FLS_RECURSIVE",
                1,
                floor=0,
                ceiling=1,
            )
        )
        fls_max_depth = get_int(
            "AGENTROPIX_FLS_MAX_DEPTH",
            5,
            floor=1,
            ceiling=20,
        )
        # W-048: default 0 → only emit a "deleted entry" finding when the
        # filename also trips the suspicious-name matcher.  Set to 1 to
        # restore legacy behaviour (one finding per unallocated inode).
        emit_deleted_all = bool(
            get_int(
                "AGENTROPIX_FS_EMIT_DELETED_ALL",
                0,
                floor=0,
                ceiling=1,
            )
        )

        result = await mcp_fls(str(image), recursive=fls_recursive)
        if isinstance(result, ToolError):
            return [
                Finding(
                    source="filesystem.fls",
                    confidence=0.0,
                    description=f"fls failed: {result.error}",
                    evidence=f"image={image} recursive={fls_recursive} max_depth={fls_max_depth}",
                )
            ]

        findings: list[Finding] = []
        for entry in result.entries:
            name_lower = entry.name.lower()
            is_suspicious = matches_name(name_lower, file_literals, file_patterns)
            if not entry.allocated and (emit_deleted_all or is_suspicious):
                findings.append(
                    Finding(
                        source="filesystem.fls",
                        # Deleted-AND-suspicious is a stronger signal than
                        # deleted-alone, so bump confidence toward the
                        # suspicious tier when both trigger.
                        confidence=max(deleted_conf, suspicious_conf) if is_suspicious else deleted_conf,
                        description=f"Deleted entry: {entry.name}" + (" (suspicious)" if is_suspicious else ""),
                        evidence=f"inode={entry.inode} path={entry.full_path}",
                        timestamp=Finding.now(),
                        mitre_attack="T1070.004" if is_suspicious else "",
                    )
                )
            if is_suspicious:
                file_sha256 = _hash_inode(image, entry.inode)
                evidence = f"inode={entry.inode} path={entry.full_path} allocated={entry.allocated}"
                if file_sha256:
                    evidence += f" sha256={file_sha256}"
                raw = Finding(
                    source="filesystem.fls",
                    confidence=suspicious_conf,
                    description=f"Suspicious filename: {entry.name}",
                    evidence=evidence,
                    timestamp=Finding.now(),
                    mitre_attack="T1003" if "mimikatz" in name_lower else "T1105",
                    file_sha256=file_sha256,
                )
                findings.append(enriched_finding(raw))

        return findings
