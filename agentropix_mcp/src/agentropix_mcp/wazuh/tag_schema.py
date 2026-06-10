"""IOC tag schema — canonical parser for Agentropix CDB-list entries.

The Agentropix CDB push pipeline (``_make_cdb_body`` in ``orchestrator.py``)
emits one line per IOC in this format::

    <value>:<case_id>|<confidence>|<context>\n

Examples (from a live Wazuh manager run)::

    108.79.235.64:SRL-2018-MVP|high|T1071
    e18b450127de04afb3211faa456ada27:SRL-2018-MVP|medium|extracted from base-dc-cdrive.E01 triage
    rundll32.exe:SRL-2018-MVP|low|suspect interpreter

The colon separates the key from the value-part; pipes separate the three
metadata fields. The schema was introduced as orchestrator Fix 4 / S-5
(prevents the previous all-colons format from colliding with IPv6 literals).

This module is the only authoritative parser. Any code that reads CDB
contents back must use ``parse_cdb_line`` or ``parse_cdb_body`` — never
ad-hoc split.

Field semantics
---------------
* ``value``      — the raw IOC (IP, hash, image name, registry key, ...).
                   May contain colons in pathological cases (IPv6 literals);
                   parser is split-from-right on the FIRST ``:`` boundary.
* ``case_id``    — operator-scoped campaign/case identifier; serves as the
                   "actor" axis for proactive CDB seeding (tool-C in the
                   2026-05-11 4-tools evaluation). Example: ``SRL-2018-MVP``.
* ``confidence`` — ``high`` | ``medium`` | ``low`` (case-insensitive).
                   Free-form is rejected by ``_make_cdb_body`` upstream but
                   parser is tolerant.
* ``context``    — free-text. Often a MITRE ATT&CK ID (``T1071``) or a
                   forensic provenance note (``extracted from <file>``).

Sanitisation
------------
``_make_cdb_body`` strips ``:``, ``\\n``, and ``\\r`` from each of
case_id/confidence/context before writing. The parser therefore does NOT
need to defend against those characters in the metadata fields. If the
parser sees an unexpected layout it returns ``None`` (caller decides what
to do — typically log + skip).

Hash/IP comparison policy
-------------------------
For lookups, hash values are case-normalised to lowercase and stripped.
IPs and other values are compared exact-byte. The ``match`` helper handles
this without leaking the policy into the caller.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

__all__ = [
    "IOCTag",
    "parse_cdb_line",
    "parse_cdb_body",
    "match",
    "AGENTROPIX_CDB_LISTS",
    "list_for_value_kind",
]


# Canonical Agentropix CDB list names. Source of truth: the rules XML
# blocks in ``orchestrator.py`` (lines ~304-344) and the post-restart
# self-test fixtures. Any new list MUST be added here AND to the rules
# XML, or rule 100200/100201/... will not reference it.
AGENTROPIX_CDB_LISTS: tuple[str, ...] = (
    "agentropix_c2_ips",
    "agentropix_malware_md5",
    "agentropix_malware_sha256",
    "agentropix_suspect_image",
    "agentropix_persistence_regkey",
    "agentropix_suspect_module",
    # Legacy slot retained for back-compat with pre-Issue-#60 MASTER-IOCS
    # files that used kind="process_name". The orchestrator marks this
    # list as a no-op fixture (no rule references it), but live tenants
    # still carry entries here (e.g., mimikatz.exe, rundll32.exe). The
    # membership-check tool MUST cover it so an operator asking "is X on
    # our watchlist?" gets the truthful answer regardless of which
    # historical push wrote the entry.
    "agentropix_suspect_process",
    # W-203: process-tree relations lifted from memory.process_tree
    # Findings. One entry per (host, pid, parent_pid) tuple after
    # dedupe; rule registration lives in the operator's manager config.
    "agentropix_process_tree_event",
)


# Convenience mapping: value_kind -> list_name. Used by callers that
# know the IOC kind upfront and want to narrow the lookup.
_KIND_TO_LIST: dict[str, str] = {
    "ip":           "agentropix_c2_ips",
    "md5":          "agentropix_malware_md5",
    "sha256":       "agentropix_malware_sha256",
    "image":        "agentropix_suspect_image",
    "regkey":       "agentropix_persistence_regkey",
    "module":       "agentropix_suspect_module",
    # Issue #60 legacy form.
    "process_name": "agentropix_suspect_process",
}


def list_for_value_kind(kind: str) -> str | None:
    """Return the canonical CDB list for an IOC kind, or None if unknown."""
    return _KIND_TO_LIST.get(kind.lower().strip())


@dataclass(frozen=True)
class IOCTag:
    """One parsed CDB row."""

    value: str
    case_id: str
    confidence: str
    context: str

    def as_dict(self) -> dict:
        return {
            "value":      self.value,
            "case_id":    self.case_id,
            "confidence": self.confidence,
            "context":    self.context,
        }


def parse_cdb_line(line: str) -> IOCTag | None:
    """Parse one CDB row. Returns ``None`` on malformed input.

    Split policy: first ``:`` from the LEFT separates key from value-part.
    This is the inverse of ``_make_cdb_body`` (which uses the same
    boundary on emission).

    The value-part is then split on ``|`` into exactly three fields:
    ``case_id|confidence|context``. Fewer than 3 pipes -> unparseable.
    More than 3 -> extra pipes belong to ``context`` (joined back).
    """
    if not line:
        return None
    stripped = line.rstrip("\n").rstrip("\r")
    if not stripped:
        return None

    # First colon from left -> separates key from value-part.
    sep = stripped.find(":")
    if sep <= 0:
        return None

    key = stripped[:sep]
    value_part = stripped[sep + 1:]
    if not key or not value_part:
        return None

    pipes = value_part.split("|")
    if len(pipes) < 3:
        return None

    case_id = pipes[0]
    confidence = pipes[1]
    # Re-join any extra pipes back into context (defensive — emitter
    # strips pipes from context, but be tolerant).
    context = "|".join(pipes[2:])

    return IOCTag(
        value=key,
        case_id=case_id,
        confidence=confidence,
        context=context,
    )


def parse_cdb_body(body: bytes | str) -> list[IOCTag]:
    """Parse a full CDB list body into IOCTag rows.

    Tolerant of UTF-8 vs bytes input. Unparseable lines are silently
    dropped (caller can compare ``len(result)`` vs ``body.splitlines()``
    if a count is needed).
    """
    if isinstance(body, bytes):
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            text = body.decode("utf-8", errors="replace")
    else:
        text = body

    out: list[IOCTag] = []
    for raw_line in text.splitlines():
        parsed = parse_cdb_line(raw_line)
        if parsed is not None:
            out.append(parsed)
    return out


def _normalise_for_match(value: str, kind_hint: str | None) -> str:
    """Lowercase + strip for hashes; strip-only otherwise.

    Hashes are case-insensitive (MD5/SHA256 are hex). IPs, image names,
    registry keys are case-sensitive on the wire.
    """
    v = value.strip()
    if kind_hint and kind_hint.lower() in ("md5", "sha256", "sha1"):
        return v.lower()
    # Heuristic: pure-hex strings of length 32/40/64 are hashes regardless
    # of caller hint.
    if len(v) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in v):
        return v.lower()
    return v


def match(needle: str, candidates: Iterable[IOCTag], kind_hint: str | None = None) -> list[IOCTag]:
    """Return all candidates whose ``value`` equals ``needle`` under the
    kind-appropriate normalisation.
    """
    n = _normalise_for_match(needle, kind_hint)
    matches: list[IOCTag] = []
    for c in candidates:
        if _normalise_for_match(c.value, kind_hint) == n:
            matches.append(c)
    return matches
