"""RegRipper wrapper — registry hive analysis via rip.pl.

RegRipper runs Perl plugins against a registry hive (SAM, SOFTWARE,
SYSTEM, NTUSER.DAT, etc.) and emits human-readable text. The wrapper
is intentionally permissive about hive type: rip.pl validates the hive
itself, so the caller can pass any of the standard hive paths.

Output normalization captures one `RegistryEntry` per plugin section.
We extract the LastWrite timestamp and a one-line summary; the full
plugin output is preserved on the entry as `raw` so agents can mine
deeper if needed.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import shutil
from difflib import get_close_matches
from pathlib import Path

from pydantic import BaseModel, Field

from agentropix_mcp._env import get_float, get_int

logger = logging.getLogger(__name__)

TOOL_NAME = "rip.pl"

# RegRipper plugin install locations (deb + source layouts). Used to suggest
# valid plugin names when a caller requests one that isn't installed (ISSUE-006).
_PLUGIN_DIRS = (
    "/usr/share/regripper/plugins",
    "/usr/lib/regripper/plugins",
)


def _list_installed_plugins(rip_path: str | None = None) -> list[str]:
    """Return sorted names of installed RegRipper plugins (``.pl`` stems).

    Looks beside the resolved ``rip.pl`` first, then the standard dirs.
    """
    dirs: list[Path] = []
    if rip_path:
        dirs.append(Path(rip_path).resolve().parent / "plugins")
    dirs.extend(Path(d) for d in _PLUGIN_DIRS)
    names: set[str] = set()
    for d in dirs:
        try:
            if d.is_dir():
                names.update(p.stem for p in d.glob("*.pl"))
        except OSError:
            continue
    return sorted(names)


# EWF/E01 container magic bytes — first 8 bytes of any EWF family image
_EWF_MAGIC = b"EVF\x09\x0d\x0a\xff\x00"


class RegistryEntry(BaseModel):
    """One plugin's findings against a hive."""

    plugin: str
    key_path: str = ""
    last_write: str = ""
    summary: str = ""
    raw: str = ""
    # NIST1 ISSUE-006: True when this plugin crashed (rip.pl printed
    # "Error in <plugin>: ...") so a Perl exception isn't mistaken for data.
    had_error: bool = False
    # NIST1 RUN2 ISSUE-011: True when this plugin's body exceeded the per-entry
    # raw cap and was truncated (e.g. samparse with many accounts) — flagged so
    # the truncation isn't mistaken for the end of the record.
    raw_truncated: bool = False


class RegistryReport(BaseModel):
    """Parsed RegRipper output."""

    image_path: str
    hive: str
    profile: str = ""
    entry_count: int = 0
    entries: list[RegistryEntry] = Field(default_factory=list)
    tool: str = "regripper.rip"
    raw_stderr: str = ""
    # SIFT-W-082: SHA-256 of rip.pl's raw stdout bytes.
    raw_stdout_sha256: str = ""


_PLUGIN_HEADER = re.compile(r"^Launching\s+(\S+)\s+v\.[\d.]+", re.MULTILINE)
_KEY_LINE = re.compile(r"^([A-Za-z_][\w\\\-./]*\\[\w\\\-./{}]+)$", re.MULTILINE)
# W-115 hardening: require either the ``Time`` keyword OR a ``:`` /
# ``=`` separator after ``LastWrite`` so prose like "Lists services by
# LastWrite times" doesn't match and capture "times" as a fake
# timestamp. Real plugin output uses one of:
#   - ``LastWrite Time: <ts>``    (most current plugins)
#   - ``LastWrite Time = <ts>``   (some older plugins)
#   - ``LastWrite Time <ts>``     (older plugins, whitespace-only)
#   - ``LastWrite: <ts>``         (a few plugins drop ``Time``)
# The case-sensitive ``Time`` discriminator excludes lowercase prose
# like "by LastWrite times" because Python regex matches case-sensitively
# by default.
_LASTWRITE = re.compile(r"LastWrite(?:\s+Time|\s*[:=])\s*[:=]?\s*(.+)$", re.MULTILINE)


def _raw_cap() -> int:
    """NIST1 RUN2 ISSUE-011: per-entry raw cap. Default 8000 (was a hard 2000
    that truncated samparse mid-record, dropping later accounts). Env-tunable
    via AGENTROPIX_REGRIPPER_RAW_CAP; floor 2000, ceiling 64000."""
    return get_int("AGENTROPIX_REGRIPPER_RAW_CAP", 8000, floor=2000, ceiling=64000)


def _parse_rip_output(output: str) -> list[RegistryEntry]:
    """Split RegRipper output into per-plugin RegistryEntry stanzas."""
    if not output.strip():
        return []
    raw_cap = _raw_cap()
    headers = list(_PLUGIN_HEADER.finditer(output))
    entries: list[RegistryEntry] = []
    for idx, match in enumerate(headers):
        plugin = match.group(1)
        start = match.end()
        end = headers[idx + 1].start() if idx + 1 < len(headers) else len(output)
        body = output[start:end].strip()
        key_match = _KEY_LINE.search(body)
        lw_match = _LASTWRITE.search(body)
        first_line = next((ln.strip() for ln in body.splitlines() if ln.strip()), "")
        entries.append(
            RegistryEntry(
                plugin=plugin,
                key_path=key_match.group(1).strip() if key_match else "",
                last_write=lw_match.group(1).strip() if lw_match else "",
                summary=first_line[:200],
                raw=body[:raw_cap],
                had_error=f"Error in {plugin}" in body or "Error in " in body,
                raw_truncated=len(body) > raw_cap,
            )
        )
    return entries


async def get_registry(
    hive: str | Path,
    *,
    profile: str | None = None,
    plugin: str | None = None,
    timeout: float | None = None,
) -> RegistryReport:
    """Run RegRipper against a registry hive.

    Args:
        hive: Path to the hive file (SAM, SOFTWARE, SYSTEM, NTUSER.DAT, …).
        profile: Profile name for `-f` (e.g. "system", "software"); selects
            the curated plugin set for that hive type. Mutually exclusive
            with `plugin` (only one is sent to rip.pl).
        plugin: Single plugin name for `-p` (e.g. "userassist"). Wins over
            `profile` if both are provided.
        timeout: Max seconds to wait for rip.pl.

    Returns:
        RegistryReport with per-plugin entries.

    Raises:
        FileNotFoundError: hive missing or rip.pl not on PATH.
        TimeoutError: rip.pl exceeds timeout.
        RuntimeError: rip.pl returns non-zero with empty stdout.

    W-115: when neither ``profile`` nor ``plugin`` is provided, the
    wrapper defaults to ``rip.pl -a`` (auto-run hive-specific plugins).
    Pre-W-115 the bare-call path emitted ``rip.pl -r <hive>`` with no
    plugin selector, which causes ``rip.pl`` to print usage and exit 0
    with no ``Launching <plugin>`` lines — surfacing as
    ``entry_count=0`` to callers (including ``agents/artifact.py``,
    which always invokes ``mcp_get_registry(dest)`` without
    plugin/profile). The ``-a`` flag is RegRipper's canonical "run
    everything applicable to this hive type" entrypoint and matches
    the artifact agent's intent.
    """
    hive_path = Path(hive)
    if not hive_path.exists():
        raise FileNotFoundError(f"Registry hive not found: {hive_path}")

    # Detect raw disk-image containers — silently passing an E01/EWF file to
    # rip.pl produces garbage output with no error (W-039).
    try:
        header = hive_path.read_bytes()[:8]
    except OSError:
        header = b""
    if header == _EWF_MAGIC:
        raise ValueError(
            f"Input is a raw EWF/E01 disk image, not a registry hive: {hive_path}. "
            "Extract the hive first with mcp_extract_files, then pass the extracted path."
        )

    if timeout is None:
        timeout = get_float("AGENTROPIX_REGRIPPER_TIMEOUT", 60.0, floor=5.0, ceiling=3600.0)

    rip_path = shutil.which(TOOL_NAME)
    if not rip_path:
        raise FileNotFoundError(f"{TOOL_NAME} not found on PATH — install regripper")

    cmd = [rip_path, "-r", str(hive_path)]
    if plugin:
        cmd.extend(["-p", plugin])
    elif profile:
        cmd.extend(["-f", profile])
    else:
        # W-115: bare call defaults to rip.pl's auto-detect mode so the
        # artifact agent (which always calls mcp_get_registry(dest)
        # without plugin/profile) gets a non-empty result instead of
        # rip.pl's silent usage-print exit.
        cmd.append("-a")

    logger.info("Running: %s", " ".join(cmd))
    # SIFT-W-NIST1-005 (BLOCKER fix): rip.pl's stream split is
    # install-dependent — on some builds the ``Launching <plugin>``
    # banners go to stderr while plugin BODIES go to stdout; on others
    # both are on stderr. Buffering the two streams separately and
    # concatenating ``stdout + stderr`` after the fact (the old W-115
    # approach) breaks whenever banners and bodies land on DIFFERENT
    # streams: every body ends up before the first banner, so the
    # split-on-``Launching`` parser drops it (single-plugin → empty
    # entry) or mashes everything into ``entries[0]`` (profile mode).
    # Merging at the FD level (stderr→stdout) lets the OS interleave
    # banners with their own bodies in real write order regardless of
    # which stream rip.pl chose, so each ``Launching`` header is
    # immediately followed by that plugin's output. Verified against the
    # NIST1 XP SYSTEM/SAM/NTUSER hives where bodies were on stdout.
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )

    try:
        merged_bytes, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        proc.kill()
        raise TimeoutError(f"rip.pl timed out after {timeout}s") from None

    merged = merged_bytes.decode(errors="replace")
    entries = _parse_rip_output(merged)

    # Raise only when rip.pl exited non-zero AND produced no parseable
    # plugin entries — genuine failures (bad hive, missing path) surface
    # as RuntimeError, while a non-zero rc with >=1 Launching header
    # still yields a usable report (rip.pl returns rc=0 on most success
    # paths; some warning paths set rc=1 with valid plugin output).
    if proc.returncode != 0 and not entries:
        detail = merged[:500]
        # NIST1 ISSUE-006: a named plugin that isn't installed gives the agent
        # no way to discover valid names. Suggest the closest installed plugins.
        if plugin and "not found" in merged.lower():
            installed = _list_installed_plugins(rip_path)
            close = get_close_matches(plugin, installed, n=5, cutoff=0.4)
            hint = close or installed[:10]
            if hint:
                detail += f" | plugin {plugin!r} not installed; did you mean: {', '.join(hint)}"
        raise RuntimeError(f"rip.pl failed (rc={proc.returncode}): {detail}")
    # W-115: surface "auto" when neither plugin nor profile was given so
    # callers can see the wrapper's chosen mode in the report.
    profile_label = plugin or profile or "auto"
    return RegistryReport(
        image_path=str(hive_path),
        hive=hive_path.name,
        profile=profile_label,
        entry_count=len(entries),
        entries=entries,
        # streams are FD-merged now; expose the tail for diagnostics.
        raw_stderr=merged[-1000:] if merged else "",
        raw_stdout_sha256=hashlib.sha256(merged_bytes).hexdigest(),
    )
