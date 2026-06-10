"""Volatility 2.6 `editbox` plugin subprocess wrapper (SIFT-W-209).

The Vol3 line never gained a port of the `editbox` plugin from Vol2.6 — the
plugin walks the Win32k USER object tree to recover the in-memory contents of
``Edit`` control widgets, which is decisive evidence in TeamSpy-class cases
(TeamViewer / RDP / IM credentials typed at a workstation that the attacker
later proxies through). Re-implementing the plugin against the Vol3 plugin
API is multi-week work; meanwhile, the upstream Vol2.6.1 plugin still works
when driven by a Python 2.7 interpreter.

This wrapper drives the legacy plugin out-of-process: it shells to a separate
Python 2.7 venv with Vol2.6 installed (sandboxing the legacy interpreter from
the SIFT Python 3.12 runtime), parses the text output, and returns a typed
Pydantic report.

The install of Vol2.6 itself is documented in ``docs/runbooks/vol26-install.md``
— the wrapper raises ``FileNotFoundError`` with a runbook pointer when the
interpreter or ``vol.py`` cannot be located, matching the existing pattern in
``regripper.py`` and ``volatility.py`` (Vol3).

Two env vars locate the sandbox:

* ``AGENTROPIX_VOL26_PYTHON`` — Python 2.7 interpreter (default
  ``/opt/vol26/venv/bin/python``)
* ``AGENTROPIX_VOL26_BIN`` — absolute path to ``vol.py`` (default
  ``/opt/vol26/vol.py``)

Two more tune the runtime:

* ``AGENTROPIX_EDITBOX_TIMEOUT_S`` — subprocess timeout (default 600s,
  floor 60s, ceiling 7200s)
* ``AGENTROPIX_EDITBOX_MAX_RECORDS`` — cap on returned ``EditBoxRecord``
  rows (default 10000, floor 1, ceiling 1000000)

Profile autodetection runs ``vol.py imageinfo`` once per image (cached on the
image's SHA-256) and the result is memoised in-process. ``imageinfo`` itself
gets the same timeout / sandbox treatment.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import signal
from pathlib import Path

from pydantic import BaseModel, Field

from agentropix_mcp._env import get_float, get_int

logger = logging.getLogger(__name__)

TOOL_NAME = "vol2.6.editbox"

_DEFAULT_PYTHON = "/opt/vol26/venv/bin/python"
_DEFAULT_BIN = "/opt/vol26/vol.py"
_DEFAULT_TIMEOUT_S = 600.0
_DEFAULT_MAX_RECORDS = 10000
_TIMEOUT_FLOOR = 60.0
_TIMEOUT_CEILING = 7200.0
_MAX_RECORDS_FLOOR = 1
_MAX_RECORDS_CEILING = 1_000_000

# The editbox plugin prints a banner of 30 ``*`` characters between records
# and a separator of 25 ``-`` characters between meta and data within each
# record (verified against
# https://raw.githubusercontent.com/volatilityfoundation/volatility/2.6.1/volatility/plugins/gui/editbox.py
# render_text()).
_RECORD_SEPARATOR = re.compile(r"^\*{20,}$", re.MULTILINE)
_META_DATA_SEPARATOR = re.compile(r"^-{20,}$", re.MULTILINE)
_KV_LINE = re.compile(r"^([A-Za-z][A-Za-z _0-9-]*?)\s*:\s*(.*)$")
_IMAGEINFO_PROFILE = re.compile(r"Suggested Profile\(s\)\s*:\s*([^\r\n,]+)", re.IGNORECASE)


# Profile autodetection is expensive (vol.py imageinfo walks the image) but
# deterministic for a given image, so memoise on the image's SHA-256. The
# cache is process-local — restarts re-run imageinfo, which matches the
# courtroom-grade chain-of-custody expectation (always seal what we ran).
_PROFILE_CACHE: dict[str, str] = {}


class EditBoxRecord(BaseModel):
    """One Edit-control widget recovered from the memory image."""

    process_id: int
    image_file_name: str = ""
    wnd_context: str = ""
    atom_class: str = ""
    is_wow64: bool = False
    is_pwd_control: bool = False
    n_chars: int = 0
    sel_start: int = 0
    sel_end: int = 0
    undo_pos: int = 0
    undo_len: int = 0
    undo_buf: str = ""
    edit_text: str = ""
    raw: str = ""


class EditBoxResult(BaseModel):
    """Structured Vol2.6 ``editbox`` plugin output."""

    image_path: str
    image_sha256: str
    image_size_bytes: int
    profile: str
    tool: str = TOOL_NAME
    record_count: int = 0
    records: list[EditBoxRecord] = Field(default_factory=list)
    truncated: bool = False
    raw_stdout_sha256: str = ""
    raw_stderr: str = ""


def _resolve_python() -> Path:
    return Path(os.environ.get("AGENTROPIX_VOL26_PYTHON", _DEFAULT_PYTHON))


def _resolve_vol_bin() -> Path:
    return Path(os.environ.get("AGENTROPIX_VOL26_BIN", _DEFAULT_BIN))


def _require_sandbox() -> tuple[Path, Path]:
    """Locate the Vol2.6 sandbox interpreter and ``vol.py``.

    Raises ``FileNotFoundError`` with a clear runbook pointer when either is
    missing.  The Python 2.7 venv is OS-level state; SIFT's pip install does
    not stage it.  Operators install it once per host via
    ``docs/runbooks/vol26-install.md`` and then point the env vars at it.
    """
    py = _resolve_python()
    vol = _resolve_vol_bin()
    if not py.exists():
        raise FileNotFoundError(
            f"Vol2.6 Python interpreter not found at {py}. "
            "Install the sandbox: see docs/runbooks/vol26-install.md "
            "(set AGENTROPIX_VOL26_PYTHON to override the default)."
        )
    if not vol.exists():
        raise FileNotFoundError(
            f"Vol2.6 vol.py not found at {vol}. "
            "Install the sandbox: see docs/runbooks/vol26-install.md "
            "(set AGENTROPIX_VOL26_BIN to override the default)."
        )
    return py, vol


def _sha256_file(path: Path, *, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


async def _run_subprocess(cmd: list[str], *, timeout: float) -> tuple[bytes, bytes, int]:
    """Run ``cmd`` under a fresh process group with a hard timeout.

    Vol2.6 spawns helper threads inside Python 2; a bare ``proc.kill()`` on
    timeout reaps only the immediate child, which can leave the imageinfo
    workers running.  ``start_new_session=True`` puts the subprocess in its
    own PGID; on timeout we ``killpg`` the whole group with SIGKILL.
    """
    logger.info("editbox: spawning %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        # Reap the whole process group; ignore errors (race where pgid is
        # already gone is fine — we just want to ensure no orphans).
        try:
            if proc.pid is not None:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            await proc.wait()
        except Exception:
            pass
        raise TimeoutError(f"Vol2.6 subprocess timed out after {timeout}s") from None
    rc = proc.returncode if proc.returncode is not None else -1
    return stdout, stderr, rc


async def _detect_profile(
    py: Path, vol: Path, image: Path, image_sha: str, *, timeout: float
) -> str:
    """Run ``vol.py imageinfo`` and return the first Suggested Profile.

    Cached on ``image_sha`` to avoid the multi-minute re-run that
    imageinfo costs on large memory dumps.
    """
    cached = _PROFILE_CACHE.get(image_sha)
    if cached:
        logger.debug("editbox: profile cache hit %s -> %s", image_sha[:12], cached)
        return cached

    cmd = [str(py), str(vol), "-f", str(image), "imageinfo"]
    stdout, stderr, rc = await _run_subprocess(cmd, timeout=timeout)
    text = stdout.decode(errors="replace") + "\n" + stderr.decode(errors="replace")
    match = _IMAGEINFO_PROFILE.search(text)
    if not match:
        raise RuntimeError(f"Vol2.6 imageinfo did not suggest a profile (rc={rc}): {text[-400:]!r}")
    profile = match.group(1).strip()
    # Re-validate the autodetected profile through the same argv-injection
    # guard used for caller-supplied profiles: imageinfo's stdout is derived
    # from an untrusted memory image, so a crafted "Suggested Profile" string
    # must never reach vol.py's argv unchecked.
    if not re.fullmatch(r"[A-Za-z0-9_]+", profile):
        raise RuntimeError(
            f"Vol2.6 imageinfo suggested an implausible profile {profile!r} "
            "(expected [A-Za-z0-9_]+); refusing to pass it to vol.py."
        )
    _PROFILE_CACHE[image_sha] = profile
    logger.info("editbox: detected profile %s for %s", profile, image_sha[:12])
    return profile


def _parse_kv_block(block: str) -> dict[str, str]:
    """Extract ``key: value`` pairs from a record block."""
    pairs: dict[str, str] = {}
    for line in block.splitlines():
        m = _KV_LINE.match(line.strip())
        if not m:
            continue
        key = m.group(1).strip().lower().replace(" ", "_").replace("-", "_")
        pairs[key] = m.group(2).strip()
    return pairs


def _coerce_int(raw: str, default: int = 0) -> int:
    if not raw:
        return default
    raw = raw.strip()
    try:
        if raw.lower().startswith("0x"):
            return int(raw, 16)
        return int(raw)
    except ValueError:
        return default


def _coerce_bool(raw: str) -> bool:
    return raw.strip().lower() in {"yes", "true", "1"}


def _parse_record(block: str) -> EditBoxRecord | None:
    """Parse one editbox record (block between ``****`` separators).

    The record has up to two sub-sections separated by a ``-----`` divider:
    the metadata key/value block and the actual edit text. ``get_text()``
    output may itself span multiple lines (a multi-line edit control),
    so the data section is captured verbatim.
    """
    if not block.strip():
        return None
    parts = _META_DATA_SEPARATOR.split(block, maxsplit=1)
    meta = _parse_kv_block(parts[0])
    data_text = parts[1].strip() if len(parts) == 2 else ""

    pid_raw = meta.get("process_id") or meta.get("pid", "")
    pid = _coerce_int(pid_raw, default=-1)
    if pid < 0:
        # Record without a PID is malformed (Vol2.6 always emits Process ID).
        return None

    return EditBoxRecord(
        process_id=pid,
        image_file_name=meta.get("imagefilename", ""),
        wnd_context=meta.get("wnd_context", ""),
        atom_class=meta.get("atom_class", ""),
        is_wow64=_coerce_bool(meta.get("iswow64", "")),
        is_pwd_control=_coerce_bool(meta.get("ispwdcontrol", "")),
        n_chars=_coerce_int(meta.get("nchars", "0")),
        sel_start=_coerce_int(meta.get("selstart", "0")),
        sel_end=_coerce_int(meta.get("selend", "0")),
        undo_pos=_coerce_int(meta.get("undopos", "0")),
        undo_len=_coerce_int(meta.get("undolen", "0")),
        undo_buf=meta.get("undobuf", ""),
        edit_text=data_text,
        raw=block.strip()[:4000],
    )


def _parse_editbox_output(stdout: str, *, max_records: int) -> tuple[list[EditBoxRecord], bool]:
    """Split editbox stdout into per-widget records.

    Returns ``(records, truncated)``.  ``truncated`` is True when the parser
    saw more raw blocks than ``max_records`` allowed.
    """
    if not stdout.strip():
        return [], False
    blocks = _RECORD_SEPARATOR.split(stdout)
    # First chunk is the preamble before any separator — typically the
    # vol.py "Volatility Foundation Volatility Framework 2.6.1" banner
    # plus the editbox column header. Discard if it has no ``Process ID``.
    records: list[EditBoxRecord] = []
    raw_block_count = 0
    for block in blocks:
        if "Process ID" not in block and "Wnd Context" not in block:
            continue
        raw_block_count += 1
        if len(records) >= max_records:
            continue
        rec = _parse_record(block)
        if rec is not None:
            records.append(rec)
    truncated = raw_block_count > len(records)
    return records, truncated


async def get_editbox(
    image: str | Path,
    *,
    profile: str | None = None,
    timeout: float | None = None,
    max_records: int | None = None,
) -> EditBoxResult:
    """Run the Vol2.6 ``editbox`` plugin against a Windows memory image.

    Args:
        image: Path to a Windows memory dump (`.vmem`, `.raw`, `.lime`,
            `.dmp`, `.001`). Must exist and be readable.
        profile: Optional Vol2.6 profile override (e.g. ``Win7SP1x64``).
            Skips ``imageinfo`` autodetection when supplied.
        timeout: Subprocess timeout (seconds).  ``None`` reads the
            ``AGENTROPIX_EDITBOX_TIMEOUT_S`` env var (default 600).
        max_records: Cap on returned records.  ``None`` reads
            ``AGENTROPIX_EDITBOX_MAX_RECORDS`` (default 10000).

    Returns:
        :class:`EditBoxResult` with one record per edit-control widget.

    Raises:
        FileNotFoundError: image missing OR Vol2.6 sandbox unconfigured.
        TimeoutError: subprocess exceeded the resolved timeout.
        RuntimeError: vol.py exited non-zero with no parseable output, or
            imageinfo could not propose a profile.
        ValueError: callers cannot inject a bogus profile — only
            alphanumeric + underscore are accepted (Vol2.6 profile names
            obey that grammar; anything else is a sign of argv injection).
    """
    image_path = Path(image).resolve()
    if not image_path.exists():
        raise FileNotFoundError(f"Memory image not found: {image_path}")
    if not image_path.is_file():
        raise FileNotFoundError(f"Memory image is not a regular file: {image_path}")

    if profile is not None and not re.fullmatch(r"[A-Za-z0-9_]+", profile):
        raise ValueError(
            f"Invalid Vol2.6 profile name: {profile!r}. "
            "Profiles must match [A-Za-z0-9_]+ (argv-injection guard)."
        )

    py, vol = _require_sandbox()

    if timeout is None:
        timeout = get_float(
            "AGENTROPIX_EDITBOX_TIMEOUT_S",
            _DEFAULT_TIMEOUT_S,
            floor=_TIMEOUT_FLOOR,
            ceiling=_TIMEOUT_CEILING,
        )
    if max_records is None:
        max_records = get_int(
            "AGENTROPIX_EDITBOX_MAX_RECORDS",
            _DEFAULT_MAX_RECORDS,
            floor=_MAX_RECORDS_FLOOR,
            ceiling=_MAX_RECORDS_CEILING,
        )

    image_sha = _sha256_file(image_path)
    image_size = image_path.stat().st_size

    if profile is None:
        profile = await _detect_profile(py, vol, image_path, image_sha, timeout=timeout)

    cmd = [
        str(py),
        str(vol),
        "-f",
        str(image_path),
        f"--profile={profile}",
        "editbox",
    ]
    stdout, stderr, rc = await _run_subprocess(cmd, timeout=timeout)
    stdout_text = stdout.decode(errors="replace")
    stderr_text = stderr.decode(errors="replace")

    records, truncated = _parse_editbox_output(stdout_text, max_records=max_records)

    # rc==0 with no parseable record blocks is valid (image has no edit
    # controls in memory — happens on idle desktops). rc!=0 with no
    # records is genuine failure: surface stderr.
    if rc != 0 and not records:
        raise RuntimeError(
            f"Vol2.6 editbox exited rc={rc}, no records parsed. stderr tail: {stderr_text[-500:]!r}"
        )

    return EditBoxResult(
        image_path=str(image_path),
        image_sha256=image_sha,
        image_size_bytes=image_size,
        profile=profile,
        record_count=len(records),
        records=records,
        truncated=truncated,
        raw_stdout_sha256=hashlib.sha256(stdout).hexdigest(),
        raw_stderr=stderr_text[:2000],
    )


def _reset_profile_cache() -> None:
    """Test helper: clear the in-process profile autodetect cache."""
    _PROFILE_CACHE.clear()
