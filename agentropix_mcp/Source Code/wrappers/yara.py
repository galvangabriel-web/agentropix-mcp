"""YARA signature-scanning wrapper.

Drives the system ``yara`` binary (VirusTotal/YARA 4.x, installed by
default on SIFT Workstation) against a file or directory target with one
or more compiled rulesets. Each match is returned as a typed
``YaraMatch`` row carrying the rule identifier, namespace, tags and
per-rule metadata — the minimum surface the Critic / Hunt loop needs to
correlate a YARA hit with other agents' findings.

The invocation is always:

    yara -w -g -e -r <rules>... <target>

- ``-w`` suppresses parse-time warnings (we surface errors on non-zero
  rc but we don't want compatibility warnings drowning the output).
- ``-g`` prints rule tags (space-separated, in square brackets).
- ``-e`` prints the namespace prefix on the match line.
- ``-r`` recursively scans when ``target`` is a directory (harmless on
  a single file).

``-m`` (meta) is added when ``with_meta=True`` (default). ``-s``
(matched strings) is *not* on by default: the string-dump grows the
output by one+ line per match and is rarely needed at the orchestration
layer — enable it via ``with_strings=True`` when a caller explicitly
wants the matched buffer.

Match shape from YARA 4.x is one of:

    namespace:rule [tag1,tag2,...] /path/to/file
    namespace:rule [tag1,tag2,...] [meta1="v1",meta2=42] /path/to/file

Strings (when ``-s`` is set) follow the header line, each prefixed with
``0x<offset>:``; we attach them to the *previous* match row.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import shutil
from pathlib import Path

from pydantic import BaseModel, Field

from agentropix_mcp._env import clamp_float, get_float, get_int

logger = logging.getLogger(__name__)

DEFAULT_TOOL_NAME = "yara"


def _resolve_tool() -> str:
    """Resolve the YARA binary, honouring AGENTROPIX_YARA_TOOL."""
    return os.environ.get("AGENTROPIX_YARA_TOOL", DEFAULT_TOOL_NAME)


class YaraMatch(BaseModel):
    """One rule/target match."""

    rule: str
    namespace: str = ""
    tags: list[str] = Field(default_factory=list)
    meta: dict[str, str] = Field(default_factory=dict)
    file: str
    strings: list[str] = Field(default_factory=list)


class YaraReport(BaseModel):
    """Parsed output of a yara run."""

    target: str
    rules: list[str] = Field(default_factory=list)
    match_count: int = 0
    matches: list[YaraMatch] = Field(default_factory=list)
    truncated: bool = False
    tool: str = "yara"
    tool_available: bool = True
    raw_stderr: str = ""
    # SIFT-W-082: SHA-256 of yara's raw stdout bytes.
    raw_stdout_sha256: str = ""
    # SIFT-W-086: per-rule compile failures collected when
    # scan_yara is called with skip_invalid_rules=True. Each entry
    # is {"path": str, "error": str}.
    compile_failures: list[dict] = Field(default_factory=list)


# Header line layout (with -g -e, optionally -m):
#   namespace:rule [tag,tag] [meta="v",meta=N] /abs/path
# Namespace is optional (bare rulename if rules loaded without one).
_HEADER_RE = re.compile(
    r"""^
    (?:(?P<ns>[A-Za-z_][\w.]*):)?      # optional namespace
    (?P<rule>[A-Za-z_][\w]*)           # rule identifier
    (?:\s+\[(?P<tags>[^\]]*)\])?       # optional [tag,tag,...]
    (?:\s+\[(?P<meta>[^\]]*)\])?       # optional [meta=v,meta=v,...]
    \s+(?P<path>\S.*?)                 # path (allow spaces)
    \s*$
    """,
    re.VERBOSE,
)

# Matched-strings line shape:
#   0xADDR:IDENTIFIER: content
_STRING_RE = re.compile(r"^0x[0-9A-Fa-f]+:[A-Za-z0-9_$]+:")


def _parse_meta(raw: str) -> dict[str, str]:
    """Parse YARA's metadata list — ``key="v",key=123,key=true`` shape."""
    if not raw:
        return {}
    out: dict[str, str] = {}
    # YARA separates entries with ',' and never embeds unescaped ','
    # inside quoted values in its own output, so split is safe.
    for tok in raw.split(","):
        tok = tok.strip()
        if not tok or "=" not in tok:
            continue
        key, value = tok.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        out[key] = value
    return out


def _parse_tags(raw: str) -> list[str]:
    if not raw:
        return []
    return [t.strip() for t in raw.split(",") if t.strip()]


def _parse_output(
    output: str,
    *,
    max_matches: int,
) -> tuple[list[YaraMatch], bool]:
    """Return (matches, truncated) parsed from yara stdout."""
    matches: list[YaraMatch] = []
    truncated = False
    current: YaraMatch | None = None

    for line in output.splitlines():
        if not line.strip():
            continue
        if _STRING_RE.match(line):
            if current is not None:
                current.strings.append(line.rstrip())
            continue
        m = _HEADER_RE.match(line)
        if not m:
            # Not a header, not a string — YARA prints "warning: ..." and
            # "error: ..." prefixes to stderr by default. Anything slipping
            # through on stdout we preserve on the prior row if any, or
            # silently drop.
            if current is not None:
                current.strings.append(line.rstrip())
            continue
        if len(matches) >= max_matches:
            truncated = True
            break
        match = YaraMatch(
            rule=m.group("rule"),
            namespace=m.group("ns") or "",
            tags=_parse_tags(m.group("tags") or ""),
            meta=_parse_meta(m.group("meta") or ""),
            file=m.group("path"),
        )
        matches.append(match)
        current = match

    return matches, truncated


async def scan_yara(
    target: str | Path,
    rules: list[str] | list[Path],
    *,
    with_meta: bool = True,
    with_strings: bool = False,
    max_matches: int | None = None,
    timeout: float | None = None,
    skip_invalid_rules: bool = False,
) -> YaraReport:
    """Scan ``target`` with ``rules`` and return a typed ``YaraReport``.

    Args:
        target: File or directory to scan.
        rules: One or more ``.yar`` / ``.yara`` / compiled ``.yarc``
            ruleset paths. Each must exist.
        with_meta: Include ``-m`` (rule metadata) on the invocation.
        with_strings: Include ``-s`` (matched strings) on the invocation.
        max_matches: Cap on returned matches. Defaults to
            ``AGENTROPIX_YARA_MAX_MATCHES`` (1000, floor 1, ceil 100000).
        timeout: Wrapper-level subprocess timeout in seconds. ``None``
            (default) reads ``AGENTROPIX_YARA_TIMEOUT`` (300 s, floor 5,
            ceil 3600). An explicit override is clamped to the same
            ``[5, 3600]`` window — operators raising the per-call timeout
            for a 17 GB MAIL image still cannot bypass the documented
            ceiling. SIFT-W-099.
        skip_invalid_rules: SIFT-W-086. When ``True``, each rule path is
            pre-compiled via the ``yara`` Python module before invoking
            the subprocess. Rules that fail to compile are dropped from
            the command line and recorded in
            ``YaraReport.compile_failures`` instead of taking down the
            whole scan. Use this when rotating community rule packs or
            consuming untrusted rule sources where any single stale rule
            would otherwise cause the binary to exit non-zero with empty
            stdout. Default ``False`` preserves the legacy "fail-fast"
            behavior — every rule must compile cleanly or the subprocess
            decides the outcome.

    Raises:
        FileNotFoundError: target or any rules path missing, or tool not
            on PATH.
        RuntimeError: yara exits non-zero with no stdout.
        TimeoutError: subprocess exceeds ``timeout``.
    """
    target_path = Path(target)
    if not target_path.exists():
        raise FileNotFoundError(f"target not found: {target_path}")

    if not rules:
        raise ValueError("at least one YARA rules file is required")

    rule_paths: list[Path] = []
    for rule in rules:
        rp = Path(rule)
        if not rp.exists():
            raise FileNotFoundError(f"rules file not found: {rp}")
        rule_paths.append(rp)

    if timeout is None:
        timeout = get_float(
            "AGENTROPIX_YARA_TIMEOUT",
            300.0,
            floor=5.0,
            ceiling=3600.0,
        )
    else:
        timeout = clamp_float(
            "AGENTROPIX_YARA_TIMEOUT",
            float(timeout),
            floor=5.0,
            ceiling=3600.0,
        )
    if max_matches is None:
        max_matches = get_int(
            "AGENTROPIX_YARA_MAX_MATCHES",
            1000,
            floor=1,
            ceiling=100_000,
        )

    tool_name = _resolve_tool()
    tool_path = shutil.which(tool_name)
    if tool_path is None:
        raise FileNotFoundError(f"{tool_name} not found on PATH — install YARA or set AGENTROPIX_YARA_TOOL")

    # SIFT-W-086: per-rule pre-compile isolation. Without this, one stale
    # rule in a community pack causes the yara binary to exit rc=1 with
    # empty stdout, which the wrapper otherwise re-raises as RuntimeError
    # — silently zeroing the entire scan from the caller's perspective.
    compile_failures: list[dict] = []
    valid_rule_paths: list[Path] = list(rule_paths)
    if skip_invalid_rules:
        try:
            import yara as _yara_lib  # type: ignore[import-not-found]
        except Exception as exc:  # pragma: no cover — yara-python missing
            logger.warning("skip_invalid_rules=True but yara-python not importable: %s", exc)
            _yara_lib = None  # type: ignore[assignment]

        if _yara_lib is not None:
            valid_rule_paths = []
            for rp in rule_paths:
                try:
                    _yara_lib.compile(filepath=str(rp))
                except Exception as exc:
                    compile_failures.append(
                        {"path": str(rp), "error": str(exc)[:500]}
                    )
                    logger.warning(
                        "Skipping rule %s — compile failed: %s",
                        rp,
                        str(exc)[:200],
                    )
                    continue
                valid_rule_paths.append(rp)

            # Edge case: every rule failed to compile. There's nothing to
            # hand the subprocess, so return a clean empty report rather
            # than letting yara error out on a no-rules invocation.
            if not valid_rule_paths:
                return YaraReport(
                    target=str(target_path),
                    rules=[str(rp) for rp in rule_paths],
                    match_count=0,
                    matches=[],
                    truncated=False,
                    tool_available=True,
                    raw_stderr="",
                    raw_stdout_sha256="",
                    compile_failures=compile_failures,
                )

    cmd: list[str] = [tool_path, "-w", "-g", "-e", "-r"]
    if with_meta:
        cmd.append("-m")
    if with_strings:
        cmd.append("-s")
    cmd.extend(str(rp) for rp in valid_rule_paths)
    cmd.append(str(target_path))

    logger.info("Running: %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        proc.kill()
        raise TimeoutError(f"{tool_name} timed out after {timeout}s") from None

    stdout = stdout_bytes.decode(errors="replace")
    stderr = stderr_bytes.decode(errors="replace")

    # YARA uses rc=0 for "scanned, no issues", rc=1 when at least one
    # error occurs during compile/scan. It does NOT use rc to signal
    # "matches found" vs "no matches found". Treat rc!=0 with empty
    # stdout as a hard failure; tolerate rc!=0 with stdout (partial
    # scan that hit a bad rule but still produced matches).
    if proc.returncode != 0 and not stdout.strip():
        raise RuntimeError(f"{tool_name} failed (rc={proc.returncode}): {stderr[:500]}")

    matches, truncated = _parse_output(stdout, max_matches=max_matches)

    return YaraReport(
        target=str(target_path),
        rules=[str(rp) for rp in rule_paths],
        match_count=len(matches),
        matches=matches,
        truncated=truncated,
        tool_available=True,
        raw_stderr=stderr[:1000] if stderr else "",
        raw_stdout_sha256=hashlib.sha256(stdout_bytes).hexdigest(),
        compile_failures=compile_failures,
    )
