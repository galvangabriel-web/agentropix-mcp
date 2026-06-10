"""Shared credential-redaction layer (W-203 lands; W-205 + W-207 consume).

Walks an arbitrary dict / list / scalar tree, replaces credential-pattern
matches with ``[REDACTED-<tag>]`` where ``<tag>`` is the first 16 hex
characters of ``HMAC-SHA256(REDACTOR_KEY, original_bytes)``.

Defensive contracts (per DESIGNS/W-203-design.md §1.3 + §4 round-4 c4-F5):

* ``MAX_DEPTH = 32`` — cycle / recursion guard. Exceeding depth raises
  ``RedactionError("max_depth_exceeded")``.
* ``MAX_VALUE_BYTES = 1 << 20`` (1 MB per scalar) — oversize scalar
  becomes ``[REDACTED-OVERSIZE-<tag>]`` (graceful, not fatal).
* ``MAX_REGEX_INPUT_BYTES = 64 KiB`` — ReDoS guard when the optional
  ``regex`` package (with timeout=) is unavailable. Stdlib ``re`` has
  no timeout; the size cap is the only practical defence.
* Fail-closed: any uncaught exception is wrapped in ``RedactionError`` so
  the aggregator aborts rather than emitting unredacted output.

Key sourcing
------------

The HMAC key is read from the env var ``AGENTROPIX_REDACTOR_HMAC_KEY``
on every call (so tests can monkeypatch). It must be >=32 bytes. Shorter
or missing keys raise ``RedactionError``. This is a SEPARATE key from
the MASTER-IOCS signer key (``AGENTROPIX_MASTER_IOCS_HMAC_KEY``) -- see
design §2.2 round-4 c1-F4.

Tag construction
----------------

``tag = HMAC-SHA256(key, value_bytes).hexdigest()[:16]`` -- 16 hex chars
= 64 bits. Round-4 c1-F2 fix (was 8 hex / preimage-vulnerable plain
SHA-256). No ``raw_sha256`` field is emitted (round-4 c1-F1: full
SHA-256 of low-entropy values is preimage-recoverable).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from typing import Any

__all__ = ["redact_finding", "RedactionError", "REDACTOR_KEY_ENV"]


REDACTOR_KEY_ENV = "AGENTROPIX_REDACTOR_HMAC_KEY"
MAX_DEPTH = 32
MAX_VALUE_BYTES = 1 << 20  # 1 MB per scalar
MAX_REGEX_INPUT_BYTES = 64 * 1024  # 64 KiB ReDoS guard
_REDACTOR_KEY_MIN_BYTES = 32


class RedactionError(Exception):
    """Raised on any redactor failure (fail-closed contract)."""


# ---------------------------------------------------------------------------
# Credential pattern set
# ---------------------------------------------------------------------------
#
# Each entry is a compiled regex. ``match.group(0)`` is replaced by the
# redaction tag. Where the pattern wants to preserve a prefix (e.g., keep
# ``password=`` visible and only redact the value), the group named
# ``secret`` is replaced; everything else is preserved.
#
# All regexes are written to avoid catastrophic backtracking on adversarial
# inputs (no nested unbounded quantifiers over overlapping classes).
# ---------------------------------------------------------------------------

# Round-4 c1-F10: cleartext-password flags. Long-form (--password=val,
# --password val), short-form (-p val), slash-form (/password:val),
# PowerShell -Password 'val'. The secret span is captured separately so
# the flag text is preserved.
_PASSWORD_FLAG = re.compile(
    r"""(?ix)
    (?P<prefix>
        (?:--|/)password\s*[=:]\s*
      | (?:--|/)pwd\s*[=:]\s*
      | (?:--|/)passwd\s*[=:]\s*
      | (?:--|/)password\s+
      | (?:--|/)pwd\s+
      | (?:--|/)passwd\s+
      | -p\s+
      | -Password\s+
    )
    (?P<secret>'[^'\n]{1,256}'|"[^"\n]{1,256}"|\S{1,256})
    """,
)

# Generic key=value password / pwd / passwd / token / api[-_]?key / bearer /
# secret. Stops at whitespace, semicolon, comma, ampersand, or matching quote.
_PASSWORD_KV = re.compile(
    r"""(?ix)
    \b(?P<key>password|pwd|passwd|secret|token|api[-_]?key|bearer|apikey)\b
    \s*[=:]\s*
    (?P<secret>'[^'\n]{1,256}'|"[^"\n]{1,256}"|[^\s;,&'"]{1,256})
    """,
)

# PowerShell ConvertTo-SecureString -AsPlainText '<value>'.
_PWSH_SECURESTRING = re.compile(
    r"""(?ix)
    ConvertTo-SecureString
    \s+(?:.*?\s+)?
    -AsPlainText\s+
    (?P<secret>'[^'\n]{1,256}'|"[^"\n]{1,256}"|\S{1,256})
    """,
)

# NTLM / LM hash pair: 32:32 hex. Round-4 c1-F5: NTLMv2 net challenges
# get their own pattern below.
_NTLM_HASH = re.compile(
    r"(?i)\b[a-f0-9]{32}:[a-f0-9]{32}\b",
)

# user::DOMAIN:challenge:response -- NTLMv2 net challenge format. The
# response field has variable length (typically 64+ hex chars).
_NTLMV2_NET = re.compile(
    r"(?i)\b[A-Za-z0-9._\-]{1,64}::[A-Za-z0-9._\-]{1,64}:[a-f0-9]{8,}:"
    r"[a-f0-9]{32}:[a-f0-9]{32,}",
)

# Kerberos ticket / hash markers.
_KRB5 = re.compile(
    r"\$krb5(?:tgs|asrep|tgt)\$[^\s]{4,}",
    re.IGNORECASE,
)
_KRB5_TAG = re.compile(r"\bKRB5-\S+", re.IGNORECASE)

# AWS access key ID + secret-access-key kv form.
_AWS_KEY_ID = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_AWS_SECRET = re.compile(
    r"""(?ix)
    aws[_-]?secret(?:[_-]?access[_-]?key)?\s*[:=]\s*
    (?P<secret>'[A-Za-z0-9/+=]{40}'|"[A-Za-z0-9/+=]{40}"|[A-Za-z0-9/+=]{40})
    """,
)

# JWT (round-4 c1-F5): header.payload.signature triplet in URL-safe base64.
_JWT = re.compile(
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
)

# PEM / OpenSSH BEGIN markers (round-4 c1-F5).
_PEM_BEGIN = re.compile(
    r"-----BEGIN (?:RSA |OPENSSH |DSA |EC |ENCRYPTED |PRIVATE )?"
    r"(?:PRIVATE KEY|OPENSSH PRIVATE KEY|RSA PRIVATE KEY|"
    r"DSA PRIVATE KEY|EC PRIVATE KEY)-----",
)

# URL userinfo (round-4 c1-F5): scheme://user:password@host.
_URL_USERINFO = re.compile(
    r"\b[a-zA-Z][a-zA-Z0-9+\-.]*://"
    r"(?P<userinfo>[^:/?#@\s]{1,64}:[^/?#@\s]{1,128})"
    r"@[A-Za-z0-9._\-]+",
)

# MSCASH / MSCACHE-V2 (round-4 c1-F5).
_MSCASH = re.compile(
    r"(?i)\$DCC2?\$(?:\d+#)?[A-Za-z0-9._\-]{1,64}#[a-f0-9]{32}",
)


# Order matters: longer/more-specific first so the general PASSWORD_KV
# doesn't eat a flag form's value, and SQL_CONN_PWD captures pwd=val
# before the generic kv catches it.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("pem", _PEM_BEGIN),
    ("jwt", _JWT),
    ("krb5_marker", _KRB5),
    ("krb5_tag", _KRB5_TAG),
    ("mscash", _MSCASH),
    ("ntlmv2_net", _NTLMV2_NET),
    ("ntlm", _NTLM_HASH),
    ("aws_key_id", _AWS_KEY_ID),
    ("aws_secret_kv", _AWS_SECRET),
    ("url_userinfo", _URL_USERINFO),
    ("pwsh_securestring", _PWSH_SECURESTRING),
    ("password_flag", _PASSWORD_FLAG),
    ("password_kv", _PASSWORD_KV),
)


# Patterns whose interesting bit is a named-group ``secret`` or
# ``userinfo`` -- the redactor preserves the surrounding text and only
# replaces that span.
_NAMED_SPAN: dict[str, str] = {
    "aws_secret_kv": "secret",
    "url_userinfo": "userinfo",
    "pwsh_securestring": "secret",
    "password_flag": "secret",
    "password_kv": "secret",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _load_key() -> bytes:
    raw = os.environ.get(REDACTOR_KEY_ENV)
    if raw is None:
        raise RedactionError(
            f"{REDACTOR_KEY_ENV} unset; redactor cannot tag values (fail-closed)"
        )
    key_bytes = raw.encode("utf-8") if isinstance(raw, str) else raw
    if len(key_bytes) < _REDACTOR_KEY_MIN_BYTES:
        raise RedactionError(
            f"{REDACTOR_KEY_ENV} too short ({len(key_bytes)} bytes); "
            f"floor is {_REDACTOR_KEY_MIN_BYTES} bytes"
        )
    return key_bytes


def _tag(key: bytes, value_bytes: bytes) -> str:
    digest = hmac.new(key, value_bytes, hashlib.sha256).hexdigest()
    return digest[:16]


def _redact_scalar(s: str, key: bytes) -> tuple[str, bool]:
    """Apply each pattern to ``s``; return (redacted_string, did_redact).

    Oversize scalars short-circuit to ``[REDACTED-OVERSIZE-<tag>]`` so the
    regex engine never sees adversarial input.
    """
    encoded = s.encode("utf-8", errors="replace")
    if len(encoded) > MAX_VALUE_BYTES:
        return f"[REDACTED-OVERSIZE-{_tag(key, encoded[:MAX_VALUE_BYTES])}]", True
    if len(encoded) > MAX_REGEX_INPUT_BYTES:
        # Bound regex input -- the stdlib re engine has no timeout. The
        # oversize-but-not-1MB band is rare for Finding scalars (typical
        # description+evidence is <1 KB); fall through to the safe path.
        return f"[REDACTED-OVERSIZE-{_tag(key, encoded[:MAX_VALUE_BYTES])}]", True

    out = s
    did = False
    for name, pattern in _PATTERNS:
        span_name = _NAMED_SPAN.get(name)
        matches = list(pattern.finditer(out))
        if not matches:
            continue
        did = True
        rebuilt: list[str] = []
        cursor = 0
        for m in matches:
            if span_name is not None and span_name in m.groupdict():
                span_start, span_end = m.span(span_name)
                tag = _tag(key, m.group(span_name).encode("utf-8"))
                rebuilt.append(out[cursor:span_start])
                rebuilt.append(f"[REDACTED-{tag}]")
                cursor = span_end
            else:
                start, end = m.span()
                tag = _tag(key, m.group(0).encode("utf-8"))
                rebuilt.append(out[cursor:start])
                rebuilt.append(f"[REDACTED-{tag}]")
                cursor = end
        rebuilt.append(out[cursor:])
        out = "".join(rebuilt)
    return out, did


def _walk(obj: Any, key: bytes, depth: int) -> tuple[Any, bool]:
    if depth > MAX_DEPTH:
        raise RedactionError(f"max_depth_exceeded (depth={depth})")
    if isinstance(obj, str):
        return _redact_scalar(obj, key)
    if isinstance(obj, dict):
        out_dict: dict[Any, Any] = {}
        did_any = False
        for k, v in obj.items():
            new_v, did = _walk(v, key, depth + 1)
            out_dict[k] = new_v
            did_any = did_any or did
        return out_dict, did_any
    if isinstance(obj, list):
        out_list: list[Any] = []
        did_any = False
        for v in obj:
            new_v, did = _walk(v, key, depth + 1)
            out_list.append(new_v)
            did_any = did_any or did
        return out_list, did_any
    if isinstance(obj, tuple):
        out_tuple: list[Any] = []
        did_any = False
        for v in obj:
            new_v, did = _walk(v, key, depth + 1)
            out_tuple.append(new_v)
            did_any = did_any or did
        return tuple(out_tuple), did_any
    return obj, False


def redact_finding(d: dict, *, version: str = "1") -> dict:
    """Recursively redact credentials in ``d``; return a new dict.

    Adds ``redacted: True`` and ``redactor_version: version`` at the
    root of the returned dict when at least one substitution fired.
    Otherwise sets ``redacted: False`` -- ``redactor_version`` is always
    present so downstream verifiers know the redactor ran.

    Raises
    ------
    RedactionError
        Key env var missing/too short, recursion depth exceeded, or any
        uncaught exception during traversal (fail-closed contract).
    """
    if not isinstance(d, dict):
        raise RedactionError(f"redact_finding expects dict, got {type(d).__name__}")
    try:
        key = _load_key()
        new_d, did_any = _walk(d, key, depth=0)
    except RedactionError:
        raise
    except Exception as exc:  # noqa: BLE001 -- fail-closed wrap
        raise RedactionError(f"redactor uncaught: {exc!r}") from exc
    assert isinstance(new_d, dict)
    new_d["redacted"] = bool(did_any)
    new_d["redactor_version"] = version
    return new_d
