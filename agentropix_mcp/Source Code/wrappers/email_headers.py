"""Agent-layer wrapper: EML/MSG corpus -> per-message header matrix with SPF/DKIM/DMARC.

Batch-processes a directory of .eml / .msg files and returns a structured
header matrix for each message: From, Date, Subject, Reply-To, Return-Path,
Message-ID, SPF/DKIM/DMARC authentication results, and first Received hop.
Registered as ``email_header_matrix`` in FastMCP (W-172).

Moved from ``mcp_server/wrappers/`` to ``wrappers/`` (issue #44) to fix the
upward import direction: agents/ -> wrappers/, not agents/ -> mcp_server/.

Scan results are LRU-cached per (corpus_dir, format, max_messages) so
repeated calls from multiple disk images sharing the same parent directory
within a single SIFT run are deduplicated (issue #45).  Call
``clear_email_header_cache()`` between test cases.

Tunable:
* ``AGENTROPIX_EMAIL_MATRIX_MAX_MESSAGES`` (int, default 5_000, [1, 100_000])
"""

from __future__ import annotations

import email
import email.utils
import functools
import logging
import re
from email import policy as _email_policy
from pathlib import Path

from agentropix_mcp._env import get_int

logger = logging.getLogger(__name__)

_DEFAULT_MAX_MESSAGES = 5_000

# Match any spf/dkim/dmarc result token in Authentication-Results header
_AUTH_RE = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|permerror|temperror)\b",
    re.IGNORECASE,
)

_EML_EXTENSIONS: frozenset[str] = frozenset({".eml"})
_MSG_EXTENSIONS: frozenset[str] = frozenset({".msg"})
_ALL_EXTENSIONS: frozenset[str] = _EML_EXTENSIONS | _MSG_EXTENSIONS

# OLE2 magic bytes (Outlook .msg compound document)
_OLE2_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def _parse_auth_results(header_value: str) -> dict[str, str]:
    """Extract spf/dkim/dmarc result values from an Authentication-Results header."""
    out: dict[str, str] = {}
    for m in _AUTH_RE.finditer(header_value):
        key = m.group(1).lower()
        val = m.group(2).lower()
        out.setdefault(key, val)  # first occurrence wins per RFC 7601
    return out


def _first_received(received_headers: list[str]) -> str:
    """Return the outermost (first-listed) Received header, capped at 256 chars."""
    if not received_headers:
        return ""
    return received_headers[0][:256].strip()


def _parse_eml_record(path: Path) -> dict | None:
    """Parse one .eml file and return a header-matrix record dict."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        logger.warning("email_header_matrix: cannot read %s: %s", path, exc)
        return None

    try:
        msg = email.message_from_bytes(raw, policy=_email_policy.default)
    except Exception as exc:
        logger.debug("email_header_matrix: parse error %s: %s", path, exc)
        return None

    from_header = str(msg.get("From", "")).strip()
    from_email = ""
    from_display = ""
    try:
        pairs = email.utils.getaddresses([from_header]) if from_header else []
        if pairs:
            from_display, from_email = pairs[0]
    except Exception:
        pass

    # Authentication-Results can appear multiple times (one per hop)
    auth_raw = " ".join(str(h) for h in (msg.get_all("Authentication-Results") or []))
    auth = _parse_auth_results(auth_raw)

    # Received headers are newest-first by RFC 5321
    received_raw = [str(h) for h in (msg.get_all("Received") or [])]

    return {
        "path": str(path),
        "date": str(msg.get("Date", "")).strip(),
        "from_header": from_header,
        "from_email": from_email,
        "from_display_name": from_display,
        "reply_to": str(msg.get("Reply-To", "")).strip(),
        "return_path": str(msg.get("Return-Path", "")).strip(),
        "message_id": str(msg.get("Message-ID", "")).strip(),
        "subject": str(msg.get("Subject", "")).strip(),
        "spf": auth.get("spf", "none"),
        "dkim": auth.get("dkim", "none"),
        "dmarc": auth.get("dmarc", "none"),
        "first_received_hop": _first_received(received_raw),
    }


def _parse_msg_stub_record(path: Path) -> dict | None:
    """Stub-detect .msg files via OLE2 magic byte check.

    Full extraction requires ``extract_msg`` (optional dep, not yet pinned).
    Returns a partial record with empty header fields and a ``_stub=True``
    sentinel so callers know not to trust the authentication fields.
    """
    try:
        header = path.read_bytes()[:8]
    except OSError:
        return None
    if not header.startswith(_OLE2_MAGIC):
        return None
    return {
        "path": str(path),
        "date": "",
        "from_header": "",
        "from_email": "",
        "from_display_name": "",
        "reply_to": "",
        "return_path": "",
        "message_id": "",
        "subject": "",
        "spf": "none",
        "dkim": "none",
        "dmarc": "none",
        "first_received_hop": "",
        "_stub": True,
    }


@functools.lru_cache(maxsize=64)
def _cached_scan(corpus_dir: str, fmt: str, max_messages: int) -> dict:
    """LRU-cached core scan (issue #45). Keyed on (corpus_dir, fmt, max_messages).

    Cache is intentionally on resolved max_messages so env-var changes between
    calls with different caps produce distinct cache entries. Call
    ``clear_email_header_cache()`` in test teardown to prevent cross-test bleed.
    """
    if fmt == "eml":
        exts = _EML_EXTENSIONS
    elif fmt == "msg":
        exts = _MSG_EXTENSIONS
    else:
        exts = _ALL_EXTENSIONS

    base = Path(corpus_dir)
    if not base.is_dir():
        return {
            "messages": [],
            "summary": {"error": f"not a directory: {corpus_dir}"},
        }

    paths = sorted(
        p for p in base.rglob("*") if p.suffix.lower() in exts and p.is_file()
    )

    messages: list[dict] = []
    n_spf_fail = 0
    n_dkim_fail = 0
    n_dmarc_fail = 0
    seen_dates: list[str] = []

    for path in paths:
        if len(messages) >= max_messages:
            break
        if path.suffix.lower() in _MSG_EXTENSIONS:
            rec = _parse_msg_stub_record(path)
        else:
            rec = _parse_eml_record(path)
        if rec is None:
            continue
        messages.append(rec)
        if rec.get("spf") in ("fail", "softfail"):
            n_spf_fail += 1
        if rec.get("dkim") == "fail":
            n_dkim_fail += 1
        if rec.get("dmarc") == "fail":
            n_dmarc_fail += 1
        d = rec.get("date", "")
        if d:
            seen_dates.append(d)

    unique_from = len(
        {r.get("from_email", "").lower() for r in messages if r.get("from_email")}
    )

    return {
        "messages": messages,
        "summary": {
            "n_messages": len(messages),
            "n_unique_from_emails": unique_from,
            "spf_fail_count": n_spf_fail,
            "dkim_fail_count": n_dkim_fail,
            "dmarc_fail_count": n_dmarc_fail,
            "earliest_date": min(seen_dates) if seen_dates else "",
            "latest_date": max(seen_dates) if seen_dates else "",
        },
    }


def clear_email_header_cache() -> None:
    """Evict all cached scan results. Call in pytest teardown / conftest."""
    _cached_scan.cache_clear()


def email_header_matrix(
    corpus_dir: str,
    format: str = "auto",
    max_messages: int | None = None,
) -> dict:
    """Build a per-message header matrix for a corpus of EML/MSG files.

    Scans corpus_dir recursively for .eml / .msg files and returns a
    structured dict with per-message header fields including
    SPF/DKIM/DMARC authentication results extracted from
    ``Authentication-Results`` headers.

    Results are LRU-cached per (corpus_dir, format, resolved max_messages).

    Args:
        corpus_dir: Directory to scan (recursively).
        format: ``"eml"`` (only .eml), ``"msg"`` (only .msg, stub
            detection only), or ``"auto"`` (both).
        max_messages: Cap on messages processed. Defaults to
            ``AGENTROPIX_EMAIL_MATRIX_MAX_MESSAGES`` env var
            (default 5_000, floor 1, ceiling 100_000).

    Returns:
        ``{"messages": [...], "summary": {...}}``
        where each message dict carries: path, date, from_header,
        from_email, from_display_name, reply_to, return_path,
        message_id, subject, spf, dkim, dmarc, first_received_hop.
    """
    if max_messages is None:
        max_messages = get_int(
            "AGENTROPIX_EMAIL_MATRIX_MAX_MESSAGES",
            _DEFAULT_MAX_MESSAGES,
            floor=1,
            ceiling=100_000,
        )
    fmt = (format or "auto").lower().strip()
    return _cached_scan(corpus_dir, fmt, max_messages)
