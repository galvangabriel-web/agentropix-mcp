"""Pure-function Discovery technique detectors (issue #39).

Each detector takes a list of (process_name, command_line) tuples and
returns a list of (mitre_technique_id, description, confidence) hits.

Patterns ordered from most-specific to least-specific within each
technique bucket.  All string matching is case-insensitive (callers
are expected to lower() before passing; helpers also lower() defensively).
"""

from __future__ import annotations

import ast
import re

# ---------------------------------------------------------------------------
# Compiled patterns: (technique_id, description, proc_re, cmd_re | None)
# proc_re matches the basename of the process (e.g. "net.exe")
# cmd_re matches anywhere in the command line (None = match any cmdline)
# ---------------------------------------------------------------------------

_PATTERNS: list[tuple[str, str, float, re.Pattern[str], re.Pattern[str] | None]] = []


def _add(
    technique: str,
    description: str,
    confidence: float,
    proc_pattern: str,
    cmd_pattern: str | None,
) -> None:
    proc_re = re.compile(proc_pattern, re.IGNORECASE)
    cmd_re = re.compile(cmd_pattern, re.IGNORECASE) if cmd_pattern else None
    _PATTERNS.append((technique, description, confidence, proc_re, cmd_re))


# ---- T1018 Remote System Discovery ----------------------------------------
_add("T1018", "net view (remote host enumeration)", 0.75,
     r"(?:^|[/\\])net\.exe$", r"\bnet\s+view\b")
_add("T1018", "net use (UNC path mapping)", 0.75,
     r"(?:^|[/\\])net\.exe$", r"\bnet\s+use\s+\\\\")
_add("T1018", "ping sweep (-n flag)", 0.75,
     r"(?:^|[/\\])ping\.exe$", r"\bping\b.*\s-n\b")
_add("T1018", "arp -a / arp /a (ARP cache enumeration)", 0.75,
     r"(?:^|[/\\])arp\.exe$", r"(?:-a|/a)")

# ---- T1069.001 Permission Groups Discovery: Local -------------------------
_add("T1069.001", "net localgroup (local group enumeration)", 0.75,
     r"(?:^|[/\\])net\.exe$", r"\bnet\s+localgroup\b")
_add("T1069.001", "whoami /groups (local group membership)", 0.75,
     r"(?:^|[/\\])whoami\.exe$", r"/groups\b")
_add("T1069.001", "whoami /all (full token dump)", 0.75,
     r"(?:^|[/\\])whoami\.exe$", r"/all\b")

# ---- T1069.002 Permission Groups Discovery: Domain ------------------------
_add("T1069.002", "net group /domain (domain group enumeration)", 0.75,
     r"(?:^|[/\\])net\.exe$", r"\bnet\s+group\b.*\s/domain\b")
_add("T1069.002", "Get-ADGroup (AD group enumeration via PS)", 0.75,
     r"(?:^|[/\\])powershell(?:\.exe)?$", r"Get-ADGroup\b")
_add("T1069.002", "Get-DomainGroup (PowerView domain group)", 0.75,
     r"(?:^|[/\\])powershell(?:\.exe)?$", r"Get-DomainGroup\b")

# ---- T1083 File and Directory Discovery -----------------------------------
_add("T1083", "dir /s (recursive directory listing)", 0.65,
     r"(?:^|[/\\])cmd\.exe$", r"\bdir\b.*/s\b")
_add("T1083", "Get-ChildItem recursive (PS file discovery)", 0.65,
     r"(?:^|[/\\])powershell(?:\.exe)?$", r"Get-ChildItem\b")
_add("T1083", "gci (Get-ChildItem alias)", 0.65,
     r"(?:^|[/\\])powershell(?:\.exe)?$", r"\bgci\b")
_add("T1083", "ls -recurse (PS alias recursive listing)", 0.65,
     r"(?:^|[/\\])powershell(?:\.exe)?$", r"\bls\b.*-recurse\b")
_add("T1083", "dir -recurse (PS dir alias)", 0.65,
     r"(?:^|[/\\])powershell(?:\.exe)?$", r"\bdir\b.*-recurse\b")
_add("T1083", "tree.com/tree.exe (directory tree)", 0.65,
     r"(?:^|[/\\])tree\.(?:com|exe)$", None)

# ---- T1087.001 Account Discovery: Local -----------------------------------
_add("T1087.001", "net user (local account enumeration)", 0.75,
     r"(?:^|[/\\])net\.exe$", r"\bnet\s+user\b")
_add("T1087.001", "whoami.exe execution", 0.75,
     r"(?:^|[/\\])whoami\.exe$", None)

# ---- T1087.002 Account Discovery: Domain ----------------------------------
_add("T1087.002", "net user /domain (domain account enumeration)", 0.75,
     r"(?:^|[/\\])net\.exe$", r"\bnet\s+user\b.*\s/domain\b")
_add("T1087.002", "nltest /dclist (DC enumeration)", 0.75,
     r"(?:^|[/\\])nltest\.exe$", r"/dclist\b")
_add("T1087.002", "nltest /domain_trusts (trust enumeration)", 0.75,
     r"(?:^|[/\\])nltest\.exe$", r"/domain_trusts\b")
_add("T1087.002", "Get-ADUser (AD user enumeration via PS)", 0.75,
     r"(?:^|[/\\])powershell(?:\.exe)?$", r"Get-ADUser\b")
_add("T1087.002", "Get-DomainUser (PowerView domain user)", 0.75,
     r"(?:^|[/\\])powershell(?:\.exe)?$", r"Get-DomainUser\b")

# ---- T1135 Network Share Discovery ----------------------------------------
_add("T1135", "net share (local share enumeration)", 0.75,
     r"(?:^|[/\\])net\.exe$", r"\bnet\s+share\b")
_add("T1135", "net view \\\\ (remote share enumeration)", 0.75,
     r"(?:^|[/\\])net\.exe$", r"\bnet\s+view\s+\\\\")
_add("T1135", "Get-SmbShare (PS SMB share enumeration)", 0.75,
     r"(?:^|[/\\])powershell(?:\.exe)?$", r"Get-SmbShare\b")
_add("T1135", "Get-WmiObject Win32_Share (WMI share enum)", 0.75,
     r"(?:^|[/\\])powershell(?:\.exe)?$", r"Get-WmiObject\b.*Win32_Share\b")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detect_discovery(
    process_pairs: list[tuple[str, str]],
) -> list[tuple[str, str, float]]:
    """Return list of (mitre_technique_id, description, confidence) hits.

    Args:
        process_pairs: List of (process_name, command_line) tuples.
            Both values should already be lowercased for consistent
            matching; this function also lowercases defensively.
    """
    hits: list[tuple[str, str, float]] = []
    for proc, cmd in process_pairs:
        proc_l = proc.lower()
        cmd_l = cmd.lower()
        for technique, description, confidence, proc_re, cmd_re in _PATTERNS:
            if not proc_re.search(proc_l):
                continue
            if cmd_re is not None and not cmd_re.search(cmd_l):
                continue
            hits.append((technique, description, confidence))
    return hits


def parse_4688_strings(evidence: str) -> tuple[str, str]:
    """Parse process name and command line from a plaso winevtx 4688 evidence string.

    The Strings array in EID 4688 is:
      index 5 = New Process Name (full path)
      index 8 = Process Command Line (verbose auditing required)

    Returns (process_name_lower, command_line_lower).
    Returns ('', '') on parse failure or when the array is too short.
    """
    marker = "Strings: "
    idx = evidence.find(marker)
    if idx == -1:
        return ("", "")

    bracket_start = evidence.find("[", idx)
    if bracket_start == -1:
        return ("", "")

    # Find matching close bracket — scan forward, tracking nesting
    depth = 0
    bracket_end = -1
    for i in range(bracket_start, len(evidence)):
        if evidence[i] == "[":
            depth += 1
        elif evidence[i] == "]":
            depth -= 1
            if depth == 0:
                bracket_end = i
                break

    if bracket_end == -1:
        return ("", "")

    raw_list = evidence[bracket_start : bracket_end + 1]
    if len(raw_list) > 4096:
        return ("", "")
    try:
        strings: list[object] = ast.literal_eval(raw_list)
    except (ValueError, SyntaxError, RecursionError):
        return ("", "")

    if not isinstance(strings, list) or len(strings) < 6:
        return ("", "")

    proc_name = str(strings[5]).lower() if strings[5] else ""
    # index 8 may be absent (array shorter than 9) or empty (auditing off)
    cmd_line = ""
    if len(strings) >= 9:
        cmd_line = str(strings[8]).lower() if strings[8] else ""

    return (proc_name, cmd_line)


__all__ = ["detect_discovery", "parse_4688_strings"]
