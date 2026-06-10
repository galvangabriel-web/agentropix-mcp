"""Thymus Evidence Policy — read-only enforcement at the MCP boundary.

This is the architectural evidence integrity layer (S-02). The agent
physically cannot write to evidence because no MCP tool exposes a
write operation. This module adds defense-in-depth by validating that
all file paths accessed are within permitted read-only zones.
"""

from __future__ import annotations

import json
import logging
import os
from collections import deque
from datetime import UTC, datetime
from pathlib import Path

from agentropix_mcp._env import get_int

logger = logging.getLogger(__name__)

# W-091 (M8.6+): in-memory audit log is a bounded ring, not an unbounded
# list. The on-disk JSONL audit (``AGENTROPIX_AUDIT_LOG``) is the chain-
# of-custody source of truth; the in-memory copy only serves the
# ``audit_log`` inspection helper. Cap defaults to 1000 entries (~250 KB
# at typical entry size); env-var tunable for stress-test scenarios.
_AUDIT_LOG_RING_DEFAULT = 1000
_AUDIT_LOG_RING_FLOOR = 100
_AUDIT_LOG_RING_CEILING = 100_000

READONLY_PATHS = [
    "/cases/",
    "/mnt/",
    "/media/",
    "/evidence/",
    "/tmp/agentropix-sift-",
    # YARA tooling paths — root-owned, immutable to the agent. Including
    # them by default lets ``scan_yara`` consume the standard SIFT-shipped
    # rule directories without an env-var override on every deploy.
    # SIFT-W-080 (2026-04-25): prior default omitted these and every
    # scan_yara call against /usr/share/yara*/ rules tripped Thymus.
    "/usr/share/yara/rules/",
    "/usr/share/yara-rules/",
]

FORBIDDEN_PATTERNS = [
    "..",       # path traversal
    "~",        # home directory expansion
    "/dev/",    # device files
    "/proc/",   # proc filesystem
    "/sys/",    # sysfs
]

# SIFT-W-109: Linux PATH_MAX is 4096; reject longer paths with a typed REJECT
# rather than letting the OS raise ENAMETOOLONG inside a wrapper.
_PATH_MAX_BYTES = 4096


class ThymusEvidencePolicy:
    """Enforces read-only access to evidence paths.

    All MCP tool calls pass through this policy before executing.
    Writes are structurally impossible (no write tools exist), but
    this validates that read paths are within allowed zones.

    Auto-detection: when enabled, the policy automatically adds the
    parent directory of any image file to the allowed list on first
    access. This eliminates the need for manual configure_policy()
    calls while keeping the allowlist audit-visible.
    """

    # Cap on auto-detected prefixes to prevent prefix explosion
    _MAX_AUTO_PREFIXES = int(os.environ.get("AGENTROPIX_MAX_AUTO_PREFIXES", "50"))

    def __init__(
        self,
        extra_allowed: list[str] | None = None,
        auto_detect: bool = True,
        max_auto_prefixes: int | None = None,
    ) -> None:
        self._allowed_prefixes = list(READONLY_PATHS)
        if extra_allowed:
            self._allowed_prefixes.extend(extra_allowed)
        # AGENTROPIX_THYMUS_ALLOWED_PREFIXES — comma- or colon-separated
        # list of additional prefixes the operator wants pre-allowed
        # (typical use: a per-case directory like the SRL-2018 dataset).
        # Each entry is normalized to end with "/" so the prefix-match
        # is unambiguous (a sibling dir like ``/case-foo`` shouldn't
        # match against ``/case`` if the operator intended only the
        # latter). Whitespace per entry is trimmed; empty entries are
        # dropped. Documented in
        # `docs/runbooks/expose-fastmcp-tailnet.md` step 4.
        env_raw = os.environ.get("AGENTROPIX_THYMUS_ALLOWED_PREFIXES", "").strip()
        if env_raw:
            for sep in (",", ":"):
                if sep in env_raw:
                    parts = env_raw.split(sep)
                    break
            else:
                parts = [env_raw]
            for raw in parts:
                token = raw.strip()
                if not token:
                    continue
                if not token.endswith("/"):
                    token = token + "/"
                if token not in self._allowed_prefixes:
                    self._allowed_prefixes.append(token)
        self._static_prefix_count = len(self._allowed_prefixes)
        self._auto_detect = auto_detect
        self._max_auto_prefixes = max_auto_prefixes or self._MAX_AUTO_PREFIXES
        self._auto_prefix_count = 0
        ring_size = get_int(
            "AGENTROPIX_THYMUS_AUDIT_LOG_RING_SIZE",
            _AUDIT_LOG_RING_DEFAULT,
            floor=_AUDIT_LOG_RING_FLOOR,
            ceiling=_AUDIT_LOG_RING_CEILING,
        )
        self._audit_log: deque[dict[str, str]] = deque(maxlen=ring_size)

    # File extensions recognized as forensic evidence images
    _EVIDENCE_EXTENSIONS = frozenset({
        ".e01", ".dd", ".raw", ".img", ".vmdk", ".qcow2",
        ".aff", ".aff4", ".mem", ".dmp", ".lime",
    })

    def _auto_allow_parent(self, path: str) -> bool:
        """Auto-detect and allow the parent directory of an evidence image.

        Only triggers for recognized forensic image extensions.
        Returns True if a new prefix was added.
        Enforces max_auto_prefixes to prevent prefix explosion.
        """
        if not self._auto_detect:
            return False
        p = Path(path)
        if p.suffix.lower() not in self._EVIDENCE_EXTENSIONS:
            return False
        parent = str(p.resolve().parent) + "/"
        if parent in self._allowed_prefixes:
            return False
        if self._auto_prefix_count >= self._max_auto_prefixes:
            self._log(
                "AUTO_DENY",
                path,
                f"auto-detect limit reached ({self._max_auto_prefixes} prefixes)",
            )
            return False
        self._allowed_prefixes.append(parent)
        self._auto_prefix_count += 1
        self._log("AUTO_ALLOW", path, f"auto-detected evidence directory: {parent}")
        return True

    @staticmethod
    def _canonicalize(path: str) -> tuple[str, str | None]:
        """Normalize an MCP-supplied path before any policy check (W-097).

        Returns ``(canonical_path, reject_reason)``. ``reject_reason`` is
        non-empty when the input fails an early integrity screen (NUL
        byte, non-string input, etc.) and the caller must return the
        reason as a typed REJECT instead of proceeding.

        Normalization steps (idempotent — applying twice yields the same
        result as applying once):

        1. Reject NUL bytes / control chars early (the OS layer would
           raise an opaque ``ValueError`` later; surface a clear typed
           reason here instead).
        2. URL-decode percent-encoded segments — Claude Desktop on
           Windows occasionally leaks ``%20`` into otherwise-allowlisted
           paths. Decoding here makes ``/cases/foo%20bar/x.E01`` and
           ``/cases/foo bar/x.E01`` resolve identically, eliminating
           the W-097 inconsistency.
        3. Collapse double slashes via ``os.path.normpath`` (cheap, no
           filesystem touch — the heavy ``Path.resolve()`` happens
           later in ``check_read`` and benefits from the cleaner input).
        4. Strip trailing ``/`` so ``/cases/SRL-2018/`` and
           ``/cases/SRL-2018`` produce identical decisions through the
           rest of the pipeline.

        The function is deliberately conservative: it never *adds*
        permission, only *normalizes* the input so equivalent paths
        produce identical decisions. The downstream FORBIDDEN_PATTERNS
        + symlink + prefix checks remain authoritative.
        """
        if not isinstance(path, str):
            return "", f"path must be str, got {type(path).__name__}"

        # SIFT-W-109: bound the path length BEFORE any further work.
        # Linux PATH_MAX is 4096 bytes; longer paths cause ENAMETOOLONG
        # at open()/stat() time, which surfaces as an untyped wrapper
        # exception. Reject early with a clear REJECT_PATH_TOO_LONG.
        if len(path) > _PATH_MAX_BYTES:
            return path, f"REJECT_PATH_TOO_LONG: path exceeds PATH_MAX ({_PATH_MAX_BYTES} bytes)"

        # 1. NUL byte / control-char screen.
        if "\x00" in path:
            return path, "NUL byte in path"
        # Tab / newline in a filesystem path is almost always a typo or
        # injection; reject early with a clear reason.
        if any(ord(c) < 0x20 and c not in ("\t",) for c in path):
            # Tab itself is rare-but-legal in some macOS paths; only
            # reject the harder control chars (\n, \r, \x01..\x1F).
            return path, "control char in path"

        # 2. URL decoding — only when the path actually contains a
        # percent-encoded byte. Skip the import + decode for the common
        # case (saves ~200ns on the hot path).
        canonical = path
        if "%" in canonical:
            try:
                from urllib.parse import unquote
                canonical = unquote(canonical)
            except (UnicodeDecodeError, ValueError):
                # Malformed percent-encoding → leave as-is; downstream
                # FORBIDDEN_PATTERNS / prefix check will likely reject.
                pass
            # SIFT-W-108: re-screen FORBIDDEN_PATTERNS on the URL-decoded
            # form BEFORE normpath collapses '..' segments away. Without
            # this, '/cases/.../%2e%2e/etc' decodes to '../etc' → normpath
            # to '/cases/etc' and the original traversal intent is lost.
            for pattern in FORBIDDEN_PATTERNS:
                if pattern in canonical and pattern not in path:
                    return path, f"forbidden pattern in URL-decoded path: {pattern}"

        # 3. Collapse double slashes etc. without touching the FS.
        canonical = os.path.normpath(canonical)

        # 4. Strip trailing slash (normpath already does for non-root,
        # but be defensive — root "/" must keep its slash).
        if len(canonical) > 1 and canonical.endswith("/"):
            canonical = canonical.rstrip("/")

        return canonical, None

    def check_read(self, path: str) -> str | None:
        """Validate a read path against the evidence policy.

        Args:
            path: File path to validate.

        Returns:
            None if allowed, error string if rejected.
        """
        # SIFT-W-109: bound the path length first so a multi-MB malicious
        # path doesn't waste cycles in pattern matching or normpath. Linux
        # PATH_MAX is 4096 — anything larger will hit ENAMETOOLONG at the
        # OS layer anyway; reject early with a clear typed reason.
        if isinstance(path, str) and len(path) > _PATH_MAX_BYTES:
            self._log(
                "REJECT", path[:200] + "...",
                f"REJECT_PATH_TOO_LONG: path exceeds PATH_MAX ({_PATH_MAX_BYTES} bytes)",
            )
            return (
                f"Thymus REJECT: REJECT_PATH_TOO_LONG: path exceeds PATH_MAX "
                f"({_PATH_MAX_BYTES} bytes)"
            )

        # Forbidden-pattern screen runs against the RAW path FIRST so
        # that an explicit traversal attempt like ``/cases/../etc/passwd``
        # is rejected with the precise "forbidden pattern: .." reason —
        # canonicalization (below) calls os.path.normpath which would
        # collapse the segment and hide the original intent.
        for pattern in FORBIDDEN_PATTERNS:
            if pattern in path:
                self._log("REJECT", path, f"forbidden pattern: {pattern}")
                return f"Thymus REJECT: path contains forbidden pattern '{pattern}': {path}"

        # W-097 — canonicalize so trailing slash, URL-encoded spaces,
        # and double slashes produce identical decisions across every
        # wrapper. NUL / control char rejection happens here too. The
        # FORBIDDEN_PATTERNS check above already ran on the raw form,
        # so any normpath-driven collapse can no longer hide a `..`.
        canonical, canonical_reject = self._canonicalize(path)
        if canonical_reject is not None:
            self._log("REJECT", path, canonical_reject)
            return f"Thymus REJECT: {canonical_reject}: {path!r}"
        # Use the canonical form for the remaining checks so the
        # symlink + auto-allow + prefix logic all see the same shape.
        path = canonical
        path_obj = Path(path)

        # Detect symlinks and handle broken/circular links
        try:
            is_symlink = path_obj.is_symlink()
        except (PermissionError, OSError):
            is_symlink = False

        if is_symlink:
            # Check for broken symlinks (target doesn't exist)
            try:
                target_exists = path_obj.resolve(strict=True)
            except (OSError, RuntimeError, RecursionError):
                self._log("REJECT", path, "broken or circular symlink")
                return f"Thymus REJECT: broken or circular symlink: {path}"

        # Resolve path — use strict=False so we get a resolved path even for
        # non-existent targets (broken symlinks already caught above)
        resolved = str(path_obj.resolve())

        # Check forbidden patterns against resolved path
        for pattern in FORBIDDEN_PATTERNS:
            if pattern in resolved and pattern not in path:
                self._log("REJECT", path, f"forbidden pattern in resolved path: {pattern}")
                return (
                    f"Thymus REJECT: resolved path contains forbidden pattern '{pattern}': "
                    f"{path} -> {resolved}"
                )

        if is_symlink:
            self._log("SYMLINK", path, f"symlink resolved to {resolved}")

        # Auto-detect evidence directory (adds parent to allowed list if recognized)
        self._auto_allow_parent(path)

        # Validate resolved path is within allowed zones.
        # The "+ '/'" form covers the case where ``resolved`` IS one of the
        # allowed directories itself: Path.resolve() strips trailing slashes,
        # but every prefix is normalized to end with '/' so a bare-directory
        # target (e.g. recursive run_exiftool on the allowed dir root) would
        # otherwise fail prefix-startswith. This must NOT match siblings —
        # comparing equality of (resolved + "/") to the prefix keeps the
        # check tight (e.g. "/a/Net" + "/" == "/a/Net/" but does not match
        # "/a/Net2/").
        allowed = any(
            resolved.startswith(prefix) or (resolved + "/") == prefix
            for prefix in self._allowed_prefixes
        )

        if not allowed:
            # ``path_obj.exists()`` can raise ``PermissionError`` on
            # locked-down paths (e.g. ``/root/.ssh/id_rsa``) — treat
            # any stat error as "exists, but we can't see it" so the
            # policy engine never crashes (TestThymusSymlinkValidation
            # .test_permission_error_no_crash).
            try:
                path_exists = path_obj.exists()
            except (PermissionError, OSError):
                path_exists = True
            if is_symlink:
                detail = (
                    f"REJECT_SYMLINK_TARGET_OUTSIDE_ALLOWLIST: target "
                    f"'{resolved}' not under any allowed prefix"
                )
            elif not path_exists:
                detail = "REJECT_PATH_NOT_FOUND: path does not exist on disk"
            else:
                detail = (
                    f"REJECT_OUTSIDE_ALLOWLIST: '{resolved}' not under "
                    f"any allowed prefix"
                )
            self._log("REJECT", path, detail)
            return (
                f"Thymus REJECT: {detail}: {path}"
                + (f" -> {resolved}" if is_symlink else "")
                + f". Allowed: {', '.join(self._allowed_prefixes)}"
            )

        self._log("ALLOW", path, "within read-only zone")
        return None

    def check_write(self, path: str) -> str:
        """All writes are rejected — evidence integrity is architectural.

        This method always returns an error. No MCP tool should call it;
        it exists for defense-in-depth and audit completeness.
        """
        self._log("REJECT_WRITE", path, "all writes forbidden")
        return f"Thymus REJECT: ALL writes to evidence are forbidden. Path: {path}"

    def _log(self, action: str, path: str, reason: str) -> None:
        entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "action": action,
            "path": path,
            "reason": reason,
        }
        self._audit_log.append(entry)
        log_fn = logger.info if action == "ALLOW" else logger.warning
        log_fn("Thymus %s: %s (%s)", action, path, reason)

        audit_path = os.environ.get("AGENTROPIX_AUDIT_LOG", "")
        if audit_path:
            try:
                os.makedirs(os.path.dirname(audit_path), exist_ok=True)
                with open(audit_path, "a") as f:
                    json.dump(entry, f)
                    f.write("\n")
            except OSError as e:
                logger.warning("Failed to write audit log to %s: %s", audit_path, e)

    @property
    def audit_log(self) -> list[dict[str, str]]:
        return list(self._audit_log)
