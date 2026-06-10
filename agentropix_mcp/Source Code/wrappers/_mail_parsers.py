"""Mail-format detectors and parsers for the MailAgent (issue #17).

Four formats are recognised:

* **EML** — RFC 822/5322 single-message text. Fully parsed via the stdlib
  ``email.parser`` module: subject, sender, recipients, date, plain/HTML
  bodies, attachments (filename + size + content-type).
* **MSG** — Outlook compound document (OLE2). Real extraction via
  ``extract_msg``: subject, sender, recipients, date, body, attachments.
* **PST / OST** — Outlook offline / personal storage. Real extraction
  via ``pypff`` (libpff-python): walks the folder tree, yields one
  ``MailMessage`` per enumerated message, capped by
  ``AGENTROPIX_PFF_MAX_MESSAGES``.

W-219 (2026-05-17): replaced the previous stub parsers with real
implementations. The stub names are kept as thin aliases so external
callers continue to import them, but the agent layer now calls
``parse_pst`` / ``parse_msg`` directly.

All parsers are pure functions over bytes / text — no I/O, no MCP
coupling — so the agent layer can drive them from either disk reads or
synthesised test fixtures.
"""

from __future__ import annotations

import contextlib
import email
import hashlib
import logging
import os
import re
import subprocess
import tempfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Literal

from agentropix_mcp._env import get_int

logger = logging.getLogger(__name__)


MailFormat = Literal["eml", "msg", "pst", "ost", "unknown"]


@dataclass(slots=True)
class Attachment:
    """A single attachment extracted from a mail message.

    ``mime_type`` is ``None`` when the source format does not declare one.
    ``content_hash`` is a SHA-256 of the decoded payload bytes; ``None``
    when no payload bytes were available (e.g. stub parsers, or payloads
    that failed to decode).
    """

    filename: str
    mime_type: str | None
    size: int
    content_hash: str | None = None


@dataclass(slots=True)
class MailMessage:
    """A single parsed mail message.

    Field shape is uniform across formats so detectors can iterate one
    list. The ``parser_note`` is empty on success and populated with a
    short failure / deferral reason otherwise; the agent layer fires a
    deferral finding when ``parser_note`` is non-empty.

    ``detected_charset`` carries the body charset when the parser was
    able to identify one (RFC 2822 ``Content-Type: charset=`` header,
    pypff transport headers, ``extract_msg.body_encoding``); ``None``
    when undetected.
    """

    subject: str = ""
    sender: str = ""
    recipients: list[str] = field(default_factory=list)
    date: str = ""
    body_text: str = ""
    body_html: str | None = None
    attachments: list[Attachment] = field(default_factory=list)
    source_format: MailFormat = "unknown"
    source_path: str = ""
    parser_note: str = ""
    detected_charset: str | None = None


# --- Format detection -------------------------------------------------------


# OLE2 compound document magic — used by MSG (and many other Office types).
_OLE2_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
# PST / OST magic header (``!BDN``) — same prefix for both formats.
_PST_MAGIC = b"!BDN"


def _looks_like_eml(head: bytes) -> bool:
    """Heuristic EML detection: a recognised RFC 822 header in the first
    block and no binary nulls. We avoid the strict ``email.parser`` here
    because format detection runs on every file and we want it cheap.
    """
    if b"\x00" in head[:4096]:
        return False
    sample = head[:4096].decode("utf-8", errors="replace").lstrip()
    if not sample:
        return False
    first_line = sample.split("\n", 1)[0].lower()
    eml_starts = (
        "from:",
        "received:",
        "return-path:",
        "delivered-to:",
        "message-id:",
        "subject:",
        "to:",
        "date:",
        "mime-version:",
    )
    return any(first_line.startswith(prefix) for prefix in eml_starts)


def detect_format(content: bytes) -> MailFormat:
    """Identify a mail container by magic bytes / header heuristics.

    Returns ``"unknown"`` when nothing matches; callers should fall back
    to a path-suffix hint before treating that as a hard miss.
    """
    if not content:
        return "unknown"
    if content.startswith(_PST_MAGIC):
        # PST and OST share the !BDN signature; the difference is the
        # filename suffix and a flag deeper in the header. The stub
        # parser cannot read that flag — callers disambiguate via path.
        return "pst"
    if content.startswith(_OLE2_MAGIC):
        return "msg"
    if _looks_like_eml(content):
        return "eml"
    return "unknown"


def detect_format_with_hint(content: bytes, path: Path | str) -> MailFormat:
    """Like :func:`detect_format` but lets a ``.ost`` filename suffix
    override the shared PST/OST magic disambiguation.
    """
    fmt = detect_format(content)
    suffix = Path(str(path)).suffix.lower()
    if fmt == "pst" and suffix == ".ost":
        return "ost"
    if fmt == "unknown":
        if suffix == ".eml":
            return "eml"
        if suffix == ".msg":
            return "msg"
        if suffix == ".pst":
            return "pst"
        if suffix == ".ost":
            return "ost"
    return fmt


# --- EML parser -------------------------------------------------------------


def _payload_bytes(part: EmailMessage) -> bytes:
    """Return the decoded payload bytes for ``part``; ``b""`` on failure."""
    try:
        data = part.get_payload(decode=True)
    except Exception as exc:  # malformed CTE etc — skip
        logger.debug("EML payload decode failed: %s", exc)
        return b""
    if data is None:
        return b""
    if isinstance(data, str):
        return data.encode("utf-8", errors="replace")
    return data


def _payload_text(part: EmailMessage) -> str:
    """Return text content for an EML part with charset best-effort decode."""
    raw = _payload_bytes(part)
    if not raw:
        try:
            content = part.get_content()
        except Exception:
            return ""
        if isinstance(content, str):
            return content
        if isinstance(content, bytes):
            return content.decode("utf-8", errors="replace")
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return raw.decode(charset, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


def _attachment_from_part(part: EmailMessage) -> Attachment | None:
    filename = part.get_filename()
    if not filename:
        # Some senders attach without filename — use the content-type.
        ctype = part.get_content_type()
        if ctype and "/" in ctype and part.get("Content-Disposition", "").lower().startswith("attachment"):
            filename = f"unnamed.{ctype.split('/', 1)[1]}"
        else:
            return None
    payload = _payload_bytes(part)
    digest: str | None = None
    if payload:
        digest = hashlib.sha256(payload).hexdigest()
    return Attachment(
        filename=filename,
        mime_type=part.get_content_type() or None,
        size=len(payload),
        content_hash=digest,
    )


def _split_recipients(value: str) -> list[str]:
    if not value:
        return []
    return [r.strip() for r in value.split(",") if r.strip()]


def parse_eml(content: str | bytes) -> MailMessage:
    """Parse an RFC 822/5322 message into a :class:`MailMessage`.

    Accepts either ``str`` or ``bytes`` so the agent can hand raw file
    bytes through without a pre-decode. Malformed input never raises —
    the parser returns whatever fields it could recover and leaves the
    rest blank.
    """
    if isinstance(content, str):
        content_bytes = content.encode("utf-8", errors="replace")
    else:
        content_bytes = content

    try:
        msg: EmailMessage = email.message_from_bytes(  # type: ignore[assignment]
            content_bytes, policy=policy.default
        )
    except Exception as exc:
        logger.debug("EML parse failed: %s", exc)
        return MailMessage(source_format="eml", parser_note=f"parse-error: {exc}")

    subject = str(msg.get("Subject", "")).strip()
    sender = str(msg.get("From", "")).strip()
    date = str(msg.get("Date", "")).strip()

    recipients: list[str] = []
    for header in ("To", "Cc", "Bcc"):
        recipients.extend(_split_recipients(str(msg.get(header, ""))))

    body_text = ""
    body_html: str | None = None
    attachments: list[Attachment] = []

    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue
            disposition = (part.get("Content-Disposition") or "").lower()
            ctype = part.get_content_type()
            if disposition.startswith("attachment") or part.get_filename():
                attachment = _attachment_from_part(part)
                if attachment is not None:
                    attachments.append(attachment)
                continue
            if ctype == "text/plain" and not body_text:
                body_text = _payload_text(part)
            elif ctype == "text/html" and body_html is None:
                body_html = _payload_text(part)
    else:
        ctype = msg.get_content_type()
        text = _payload_text(msg)
        if ctype == "text/html":
            body_html = text
        else:
            body_text = text

    return MailMessage(
        subject=subject,
        sender=sender,
        recipients=recipients,
        date=date,
        body_text=body_text,
        body_html=body_html,
        attachments=attachments,
        source_format="eml",
        parser_note="",
    )


# --- PST / OST parser (W-219) ----------------------------------------------
#
# pypff is read-only (the libpff C library has no writer); fixture
# generation for tests therefore relies on mocking ``pypff.file`` rather
# than producing real PST bytes. Real-corpus integration tests against
# carved PST samples are deferred to Phase 7 / W-220.


_PFF_MAX_MESSAGES_ENV = "AGENTROPIX_PFF_MAX_MESSAGES"  # floor=1, ceiling=100_000, default=10_000
_PFF_BODY_CHARS_ENV = "AGENTROPIX_PFF_BODY_CHARS"  # floor=128, ceiling=2_000_000, default=200_000
_PFF_RECOVERY_TIMEOUT_ENV = "AGENTROPIX_PFF_RECOVERY_TIMEOUT"  # floor=30, ceiling=1800, default=300
_PFF_RECOVERY_BIN_ENV = "AGENTROPIX_PFF_RECOVERY_BIN"  # pffexport binary path, default "pffexport"
_PFF_RECOVERY_MAX_MSGS_ENV = "AGENTROPIX_PFF_RECOVERY_MAX_MESSAGES"  # floor=100, ceiling=100_000, default=10_000

# SIFT-W-231: chain-of-custody knobs.
# - TMPDIR: when set, pffexport's extraction is staged under this dir
#   instead of the system tempdir. Lets operators keep sensitive
#   attachment bytes on the same volume as the case folder (some
#   forensic SOPs require this for evidence-handling continuity).
_PFF_RECOVERY_TMPDIR_ENV = "AGENTROPIX_PFF_RECOVERY_TMPDIR"
# Module-cached pffexport version string (lazily captured on first
# recovery call). Embedded in `parser_note` for audit trail —
# downstream readers can pin which extraction tool produced a row.
_PFFEXPORT_VERSION_CACHE: str | None = None
_PFFEXPORT_VERSION_RE = re.compile(r"^pffexport\s+(\d+)\s*$", re.MULTILINE)

# SIFT-W-230: operator kill switch for the W-229 pffexport-based
# recovery path. Defaults to "1" (enabled). When set to an explicit
# empty string, "0", "false", "no", or "off" (case-insensitive),
# `parse_pst_with_recovery` skips the subprocess-spawning recovery
# branch entirely — regardless of the `recover` parameter. The
# empty-string treatment follows the NO_COLOR convention: a
# deliberately-empty env var is an explicit "disable", not "unset".
#
# Prefix note: `_MAIL_*` (not `_PFF_*`) because this kill switch
# governs the full mail-recovery layer, not just libpff/pffexport
# internals. Future MSG/EML fallback paths will live under the same
# switch, which would surprise operators if it were named `_PFF_*`.
_MAIL_RECOVERY_ENABLED_ENV = "AGENTROPIX_MAIL_RECOVERY_ENABLED"
_MAIL_RECOVERY_DISABLE_VALUES = frozenset({"", "0", "false", "no", "off"})

_SUBJECT_CAP = 1024  # matches the pypff path's subject truncation; used in dedup

# SIFT-W-229: libpff defect class. When pypff raises
# `libpff_local_descriptors_node_get_entry_data: invalid local
# descriptors node` (or any sibling `local_descriptors_*` error) on a
# message, the recovery layer falls back to ``pffexport`` to extract
# the affected messages — the same defect that masked 534/544 messages
# in the SRL-2015 nromanoff PST.
_LOCAL_DESCRIPTORS_SIG = "local_descriptors"
_MESSAGE_ID_RE = re.compile(r"^Message-ID:\s*(<[^>]+>)", re.IGNORECASE | re.MULTILINE)

# SIFT-W-229 dedup helpers. pypff and pffexport disagree on the date
# field: pypff uses MAPI `delivery_time` formatted as ISO-8601 (no tz),
# pffexport surfaces the RFC 2822 `Date:` header verbatim. The two are
# also semantically distinct (delivery vs submission timestamp), so
# exact-time match is impossible — we normalize to a date prefix and
# combine with subject + sender for the dedup key.
_ISO_DATE_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})")
_RFC2822_DATE_RE = re.compile(
    r"\b(\d{1,2})\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{4})\b"
)
_MONTHS = {
    "Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04", "May": "05", "Jun": "06",
    "Jul": "07", "Aug": "08", "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12",
}

_FROM_RE = re.compile(r"<([^>]+)>|([^\s<]+@[^\s>]+)")
_CHARSET_RE = re.compile(r"charset\s*=\s*[\"']?([\w\-]+)", re.I)


def _parse_email_from_headers(headers: str) -> str:
    """Extract sender email from an RFC 2822 ``From:`` header block.

    pypff.message exposes ``transport_headers`` (raw header string) but
    has no ``sender_email_address`` attribute — we parse the canonical
    ``<addr>`` token out of the ``From:`` line, falling back to the
    first bare ``user@domain`` token if no angle-bracketed form exists.
    Returns ``""`` when no address can be recovered.
    """
    if not headers:
        return ""
    for line in headers.split("\n"):
        if line.lower().startswith("from:"):
            match = _FROM_RE.search(line)
            if match:
                return match.group(1) or match.group(2) or ""
    return ""


def _parse_recipients_from_headers(headers: str) -> list[str]:
    """Extract recipients from ``To:`` / ``Cc:`` / ``Bcc:`` header lines."""
    if not headers:
        return []
    out: list[str] = []
    for line in headers.split("\n"):
        lower = line.lower()
        if lower.startswith(("to:", "cc:", "bcc:")):
            addr_part = line.split(":", 1)[1] if ":" in line else ""
            for addr in addr_part.split(","):
                if addr.strip():
                    out.append(addr.strip())
    return out


def _detect_charset(headers: str) -> str | None:
    """Pull the charset token from a ``Content-Type:`` header, if present."""
    if not headers:
        return None
    match = _CHARSET_RE.search(headers)
    return match.group(1).lower() if match else None


def _walk_pst_folder(folder: Any) -> Iterator[Any]:
    """Yield pypff messages from a folder tree, depth-first."""
    for sub in folder.sub_folders:
        yield from _walk_pst_folder(sub)
    for i in range(folder.number_of_sub_messages):
        yield folder.get_sub_message(i)


# SIFT-W-217: MAPI property IDs for attachment filenames. pypff.attachment
# exposes no `.name` attribute — the filename lives in the MAPI record set
# under one of these property tags. Prefer the long (Unicode, full-path)
# form; fall back to the short (8.3) form. Caller supplies a positional
# `attachment_{j}` fallback when neither is present (CTF-grade encrypted
# attachments occasionally strip both tags).
_PR_ATTACH_FILENAME = 0x3704  # PT_UNICODE — short 8.3 name
_PR_ATTACH_LONG_FILENAME = 0x3707  # PT_UNICODE — full filename (preferred)


def _pypff_attachment_filename(att: Any) -> str | None:
    """Walk an attachment's MAPI record set for the filename.

    Returns the long filename if present, else the short filename, else
    ``None``. Resilient to record-entry conversion errors (one bad
    string-decode does not collapse the walk).
    """
    short_name: str | None = None
    for r in range(att.number_of_record_sets):
        record_set = att.get_record_set(r)
        for e in range(record_set.number_of_entries):
            try:
                entry = record_set.get_entry(e)
                entry_type = entry.get_entry_type()
                if entry_type == _PR_ATTACH_LONG_FILENAME:
                    long_name = entry.get_data_as_string()
                    if long_name:
                        return long_name
                elif entry_type == _PR_ATTACH_FILENAME and short_name is None:
                    short_name = entry.get_data_as_string() or None
            except (OSError, RuntimeError, UnicodeDecodeError, AttributeError) as exc:
                logger.debug(
                    "pypff MAPI entry %d in record_set %d unreadable: %s — skipping",
                    e, r, exc,
                )
                continue
    return short_name


def _pypff_message_to_mailmessage(
    pmsg: Any,
    *,
    path: Path,
    fmt: MailFormat,
    body_cap: int,
    spill_attachment: Callable[[bytes, str], Path] | None,
) -> MailMessage:
    """Convert one pypff.message into a SIFT MailMessage."""
    headers = pmsg.transport_headers or ""
    subject = (pmsg.subject or "")[:1024]
    sender_name = pmsg.sender_name or ""
    sender_email = _parse_email_from_headers(headers)
    if sender_email and sender_name:
        sender = f"{sender_name} <{sender_email}>"
    else:
        sender = sender_email or sender_name
    recipients = _parse_recipients_from_headers(headers)
    date = pmsg.delivery_time.isoformat() if pmsg.delivery_time else ""

    body_raw = pmsg.plain_text_body or pmsg.html_body or b""
    charset = _detect_charset(headers)
    if isinstance(body_raw, bytes):
        decode_charset = charset or "utf-8"
        try:
            body_text = body_raw.decode(decode_charset, errors="replace")[:body_cap]
        except LookupError:
            body_text = body_raw.decode("utf-8", errors="replace")[:body_cap]
    else:
        body_text = str(body_raw)[:body_cap]

    # SIFT-W-217: per-attachment try/except scope. A single corrupt
    # attachment (bad MAPI record set, libpff seek error inside
    # read_buffer) must not collapse the whole message — drop it with a
    # warning and continue with the remaining attachments.
    attachments: list[Attachment] = []
    for j in range(pmsg.number_of_attachments):
        try:
            a = pmsg.get_attachment(j)
            size = a.size or 0
            att_bytes = a.read_buffer(size) if size else b""
            content_hash = hashlib.sha256(att_bytes).hexdigest() if att_bytes else None
            filename = _pypff_attachment_filename(a) or f"attachment_{j}"
            if spill_attachment and att_bytes:
                spill_attachment(att_bytes, filename)
            attachments.append(
                Attachment(
                    filename=filename,
                    mime_type=None,  # pypff does not expose MIME type
                    size=size,
                    content_hash=content_hash,
                )
            )
        except (
            OSError,
            RuntimeError,
            AttributeError,
            UnicodeDecodeError,
            ValueError,
        ) as exc:
            logger.warning(
                "pypff attachment %d in %s unreadable: %s — skipping attachment",
                j, path, exc,
            )
            continue

    return MailMessage(
        subject=subject,
        sender=sender,
        recipients=recipients,
        date=date,
        body_text=body_text,
        body_html=None,
        attachments=attachments,
        source_format=fmt,
        source_path=str(path),
        parser_note="",
        detected_charset=charset,
    )


def _pst_deferral(
    content: bytes, path: Path, fmt: MailFormat, *, note: str
) -> MailMessage:
    has_magic = content.startswith(_PST_MAGIC)
    final_note = note if has_magic else f"{fmt.upper()} header missing"
    return MailMessage(
        subject="",
        sender="",
        recipients=[],
        date="",
        body_text="",
        body_html=None,
        attachments=[],
        source_format=fmt,
        source_path=str(path),
        parser_note=final_note,
        detected_charset=None,
    )


def parse_pst(
    content: bytes,
    path: Path,
    *,
    spill_attachment: Callable[[bytes, str], Path] | None = None,
) -> list[MailMessage]:
    """Parse a ``.pst`` / ``.ost`` container via pypff.

    Returns one ``MailMessage`` per enumerated message, capped by
    ``AGENTROPIX_PFF_MAX_MESSAGES`` (default 10_000). On any pypff
    failure the function returns a single deferral row with a
    ``parser_note`` containing ``pypff_failed:`` plus the verbatim
    ``pffexport`` recipe so an operator can rerun manually.

    Parameters
    ----------
    content:
        Raw file bytes (used only for the magic-header confirmation in
        the deferral path; pypff opens by path, not buffer).
    path:
        Filesystem path the bytes were read from. Must exist on disk —
        pypff has no ``open_buffer`` API.
    spill_attachment:
        Optional callback ``(bytes, suggested_name) -> Path`` invoked
        once per attachment with non-empty bytes. Phase 3 (mail-agent
        chain) supplies a tempdir-spill closure that hands the
        resulting path to ``analyze_maldoc()``. Phase 1 leaves it
        ``None`` — attachments are still emitted with ``content_hash``
        and ``size`` but their bytes are not retained.

    See also
    --------
    :func:`parse_pst_with_recovery` — same contract plus an opt-in
    ``pffexport`` fallback for messages pypff cannot read (SIFT-W-229).
    """
    messages, _ = _parse_pst_impl(content, path, spill_attachment=spill_attachment)
    return messages


def _parse_pst_impl(
    content: bytes,
    path: Path,
    *,
    spill_attachment: Callable[[bytes, str], Path] | None = None,
) -> tuple[list[MailMessage], list[str]]:
    """Internal: same walk as ``parse_pst``, but also returns the
    per-message exception strings so the W-229 recovery layer can
    decide whether to invoke ``pffexport``.

    The second tuple element is the list of ``str(exc)`` strings
    collected from the per-message ``except`` block (empty when the
    walk was clean). The first tuple element is identical to
    ``parse_pst``'s return value, deferral semantics included.
    """
    suffix = path.suffix.lower()
    fmt: MailFormat = "ost" if suffix == ".ost" else "pst"
    max_msgs = get_int(_PFF_MAX_MESSAGES_ENV, 10_000, floor=1, ceiling=100_000)
    body_cap = get_int(_PFF_BODY_CHARS_ENV, 200_000, floor=128, ceiling=2_000_000)

    import pypff  # lazy import keeps the module importable in stub-test environments

    messages: list[MailMessage] = []
    skipped_errors: list[str] = []
    pst = pypff.file()
    try:
        pst.open(str(path))
    except (OSError, RuntimeError) as exc:
        logger.warning(
            "pypff failed to open %s: %s — emitting deferral row", path, exc
        )
        return (
            [
                _pst_deferral(
                    content,
                    path,
                    fmt,
                    note=f"pypff_failed: {exc!s} — fallback: `pffexport {path}`",
                )
            ],
            [str(exc)],
        )
    try:
        root = pst.get_root_folder()
        for count, pmsg in enumerate(_walk_pst_folder(root)):
            if count >= max_msgs:
                logger.warning(
                    "PST cap %d reached at %s; remaining messages dropped",
                    max_msgs,
                    path,
                )
                break
            try:
                messages.append(
                    _pypff_message_to_mailmessage(
                        pmsg,
                        path=path,
                        fmt=fmt,
                        body_cap=body_cap,
                        spill_attachment=spill_attachment,
                    )
                )
            except (
                OSError,
                RuntimeError,
                AttributeError,
                UnicodeDecodeError,
                ValueError,
            ) as exc:
                skipped_errors.append(str(exc))
                logger.warning(
                    "pypff per-message failure at index %d in %s: %s — skipping",
                    count,
                    path,
                    exc,
                )
                continue
    finally:
        pst.close()
    if skipped_errors:
        logger.warning(
            "PST %s: %d per-message failures skipped; %d valid messages retained",
            path,
            len(skipped_errors),
            len(messages),
        )

    if not messages:
        return (
            [_pst_deferral(content, path, fmt, note="empty_message_store")],
            skipped_errors,
        )
    return messages, skipped_errors


# --- W-229: pffexport recovery fallback ------------------------------------


def _normalize_date(date_str: str) -> str:
    """Normalize a date field to ``YYYY-MM-DD`` (empty if unparseable)."""
    if not date_str:
        return ""
    iso = _ISO_DATE_RE.match(date_str)
    if iso:
        return f"{iso.group(1)}-{iso.group(2)}-{iso.group(3)}"
    rfc = _RFC2822_DATE_RE.search(date_str)
    if rfc:
        return f"{rfc.group(3)}-{_MONTHS[rfc.group(2)]}-{int(rfc.group(1)):02d}"
    return ""


def _dedup_key(m: MailMessage) -> tuple[str, str, str]:
    """Composite identity key for cross-engine MailMessage dedup.

    Used by ``parse_pst_with_recovery`` to skip pffexport-recovered
    messages that pypff already returned. ``Message-ID:`` would be
    ideal but is not consistently exposed on the pypff path; subject
    and sender are stable across engines (both read MAPI fields), and
    we use a date-only prefix for time-of-day-agnostic matching.

    Subject is truncated to ``_SUBJECT_CAP`` to match pypff's
    ``_pypff_message_to_mailmessage`` cap — without this, a
    >1024-char subject from the pffexport path (``parse_eml`` is
    uncapped) would fail to dedup against its pypff counterpart.
    """
    subject = (m.subject or "")[:_SUBJECT_CAP]
    return (subject, m.sender or "", _normalize_date(m.date))


def _pffexport_version(bin_path: str) -> str:
    """Lazily capture ``pffexport``'s version string (e.g. ``v20180714``).

    SIFT-W-231 chain-of-custody: the version is embedded into recovered
    messages' ``parser_note`` so downstream readers can pin which
    extraction tool produced a given row. Cached at module level —
    re-invoked only on the first recovery call. Returns ``"vunknown"``
    if probing fails for any reason (the recovery path proceeds; the
    marker is informational, not load-bearing).
    """
    global _PFFEXPORT_VERSION_CACHE
    if _PFFEXPORT_VERSION_CACHE is not None:
        return _PFFEXPORT_VERSION_CACHE
    try:
        # `pffexport` (no args) writes its version line to stderr then
        # exits non-zero with "Missing source file." check=False so we
        # don't raise on the expected non-zero exit.
        result = subprocess.run(
            [bin_path], capture_output=True, timeout=5, check=False,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        _PFFEXPORT_VERSION_CACHE = "vunknown"
        return _PFFEXPORT_VERSION_CACHE
    blob = (result.stderr.decode("utf-8", errors="replace")
            + "\n"
            + result.stdout.decode("utf-8", errors="replace"))
    match = _PFFEXPORT_VERSION_RE.search(blob)
    _PFFEXPORT_VERSION_CACHE = f"v{match.group(1)}" if match else "vunknown"
    return _PFFEXPORT_VERSION_CACHE


def _parse_pffexport_message_dir(
    msg_dir: Path,
    *,
    fmt: MailFormat,
    source_path: Path,
    spill_attachment: Callable[[bytes, str], Path] | None,
    pffexport_version: str,
) -> MailMessage | None:
    """Marshal one ``pffexport`` ``Message{NNNNN}/`` subdir into a
    ``MailMessage``. Returns ``None`` if the dir has neither headers
    nor a body (truly empty extraction)."""
    headers_file = msg_dir / "InternetHeaders.txt"
    body_file = msg_dir / "Message.txt"

    try:
        headers = (
            headers_file.read_text(encoding="utf-8", errors="replace")
            if headers_file.is_file() else ""
        )
        body_text = (
            body_file.read_text(encoding="utf-8", errors="replace")
            if body_file.is_file() else ""
        )
    except OSError as exc:
        logger.warning("pffexport: cannot read %s: %s", msg_dir, exc)
        return None

    if not headers and not body_text:
        return None

    # Re-use parse_eml's RFC 822 plumbing by synthesizing an EML from
    # the headers + body. parse_eml never raises — on a malformed
    # blob it returns a deferral row, which we'd surface as such.
    composed = (headers + "\n\n" + body_text).encode("utf-8", errors="replace")
    # parse_eml's documented contract is to never raise (it returns a
    # deferral MailMessage on parse failure), but the contract is
    # implicit — wrap defensively so a future regression there cannot
    # collapse the recovery of an entire message dir.
    try:
        eml_msg = parse_eml(composed)
    except Exception as exc:  # noqa: BLE001 — defensive: parse_eml is third-party-ish
        logger.warning(
            "pffexport: parse_eml failed on %s: %s — skipping recovery for this dir",
            msg_dir, exc,
        )
        return None

    extra_attachments: list[Attachment] = []
    attachments_dir = msg_dir / "Attachments"
    if attachments_dir.is_dir():
        for att_path in sorted(attachments_dir.iterdir()):
            if not att_path.is_file():
                continue
            try:
                att_bytes = att_path.read_bytes()
            except OSError as exc:
                logger.warning(
                    "pffexport: cannot read attachment %s: %s", att_path, exc,
                )
                continue
            content_hash = (
                hashlib.sha256(att_bytes).hexdigest() if att_bytes else None
            )
            if spill_attachment and att_bytes:
                spill_attachment(att_bytes, att_path.name)
            extra_attachments.append(
                Attachment(
                    filename=att_path.name,
                    mime_type=None,
                    size=len(att_bytes),
                    content_hash=content_hash,
                )
            )

    return MailMessage(
        subject=eml_msg.subject,
        sender=eml_msg.sender,
        recipients=eml_msg.recipients,
        date=eml_msg.date,
        body_text=eml_msg.body_text,
        body_html=eml_msg.body_html,
        attachments=eml_msg.attachments + extra_attachments,
        source_format=fmt,
        source_path=str(source_path),
        # ``synthesized_eml`` flags that the body was reconstructed by
        # concatenating pffexport's ``InternetHeaders.txt`` + ``Message.txt``
        # — these bytes never existed on the wire, so downstream forensic
        # consumers should treat them as best-effort text recovery, not
        # bit-faithful MAPI bytes. The trailing ``v{N}`` is the pffexport
        # version that produced the row (SIFT-W-231 chain-of-custody).
        parser_note=f"pffexport_recovered:synthesized_eml:{pffexport_version}",
        detected_charset=eml_msg.detected_charset,
    )


def _pffexport_recover(
    path: Path,
    *,
    timeout: int,
    fmt: MailFormat,
    spill_attachment: Callable[[bytes, str], Path] | None,
) -> tuple[list[MailMessage], str | None]:
    """W-229: run ``pffexport`` on ``path``, walk the resulting
    ``{target}.export/`` tree, return one ``MailMessage`` per
    ``Message{NNNNN}/`` subdir.

    Returns ``(messages, failure_reason)``. ``failure_reason`` is
    ``None`` on a successful run (even one that produced zero
    messages); on every failure mode it's a short stable tag
    (``"binary_not_found"``, ``"timeout"``, ``"subprocess_error"``,
    ``"no_output_dir"``) used by the orchestrator (SIFT-W-231) to
    emit an in-result deferral row.

    A non-zero exit is tolerated because ``pffexport`` reports
    partial-success exits (e.g. when individual messages are
    malformed) but still produces a usable output tree.
    """
    bin_path = os.environ.get(_PFF_RECOVERY_BIN_ENV, "pffexport")
    pffexport_version = _pffexport_version(bin_path)
    # SIFT-W-231: operator-configurable staging dir. When set, sensitive
    # attachment bytes never leave the case-folder volume.
    tmp_parent_raw = os.environ.get(_PFF_RECOVERY_TMPDIR_ENV) or None
    tmp_parent: str | None = tmp_parent_raw
    if tmp_parent_raw is not None and not Path(tmp_parent_raw).is_dir():
        # Fail-soft on a misconfigured env var rather than letting
        # `TemporaryDirectory(dir=...)` raise FileNotFoundError into the
        # caller — emit a deferral-row failure_reason instead so the
        # operator sees the gap in the result list (W-231 in-result
        # signaling) and recovery's "best-effort" invariant is upheld.
        logger.warning(
            "pffexport recovery: %s=%r is not a directory — skipping recovery",
            _PFF_RECOVERY_TMPDIR_ENV, tmp_parent_raw,
        )
        return [], "tmpdir_invalid"

    with tempfile.TemporaryDirectory(
        prefix="sift-pffexport-", dir=tmp_parent,
    ) as tmp_root:
        target = Path(tmp_root) / "out"
        cmd = [bin_path, "-q", "-t", str(target), "-m", "items", str(path)]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            logger.warning(
                "pffexport binary not found (%s): %s — skipping recovery",
                bin_path, exc,
            )
            return [], "binary_not_found"
        except subprocess.TimeoutExpired:
            logger.warning(
                "pffexport recovery timed out after %ds on %s — skipping",
                timeout, path,
            )
            return [], "timeout"
        except OSError as exc:
            logger.warning("pffexport subprocess error on %s: %s", path, exc)
            return [], "subprocess_error"

        export_dir = Path(f"{target}.export")
        if not export_dir.is_dir():
            logger.warning(
                "pffexport produced no output for %s (exit=%d) — skipping recovery",
                path, result.returncode,
            )
            return [], "no_output_dir"

        max_recovered = get_int(
            _PFF_RECOVERY_MAX_MSGS_ENV, 10_000, floor=100, ceiling=100_000,
        )
        recovered: list[MailMessage] = []
        for msg_dir in sorted(export_dir.rglob("Message*")):
            if not msg_dir.is_dir() or not msg_dir.name.startswith("Message"):
                continue
            if len(recovered) >= max_recovered:
                logger.warning(
                    "pffexport recovery cap %d reached on %s — remaining "
                    "message dirs dropped",
                    max_recovered, path,
                )
                break
            m = _parse_pffexport_message_dir(
                msg_dir,
                fmt=fmt,
                source_path=path,
                spill_attachment=spill_attachment,
                pffexport_version=pffexport_version,
            )
            if m is not None:
                recovered.append(m)
        return recovered, None


def _mail_recovery_enabled() -> bool:
    """Read ``AGENTROPIX_MAIL_RECOVERY_ENABLED`` as a kill switch.

    Returns ``False`` when the env var is set to one of
    ``{"0", "false", "no", "off"}`` (case-insensitive); ``True``
    otherwise (including unset). This is checked BEFORE the
    ``recover`` parameter so the operator's setting always wins —
    callers cannot accidentally re-enable recovery on a host where
    operators have disabled it.
    """
    raw = os.environ.get(_MAIL_RECOVERY_ENABLED_ENV)
    if raw is None:
        return True
    return raw.strip().lower() not in _MAIL_RECOVERY_DISABLE_VALUES


def parse_pst_with_recovery(
    content: bytes,
    path: Path,
    *,
    spill_attachment: Callable[[bytes, str], Path] | None = None,
    recover: Literal["off", "auto", "always"] = "auto",
    timeout: int | None = None,
) -> list[MailMessage]:
    """``parse_pst`` plus an opt-in ``pffexport`` recovery layer
    (SIFT-W-229).

    The libpff library raises
    ``libpff_local_descriptors_node_get_entry_data: invalid local
    descriptors node`` on PSTs whose local-descriptor tree is corrupt
    or sparsely indexed (~534/544 messages on the SRL-2015 nromanoff
    PST). ``pffexport`` reads the same PST through a different code
    path and recovers ~539/544.

    Parameters
    ----------
    recover:
        ``"off"`` — equivalent to ``parse_pst``.
        ``"auto"`` (default) — runs ``pffexport`` iff ≥1 pypff
        per-message skip mentions ``local_descriptors``.
        ``"always"`` — always runs ``pffexport`` in addition to pypff.
    timeout:
        Subprocess timeout in seconds. Defaults to
        ``AGENTROPIX_PFF_RECOVERY_TIMEOUT`` (default 300 s, floor 30,
        ceiling 1800).

    Operator kill switch (SIFT-W-230)
    ---------------------------------
    Setting ``AGENTROPIX_MAIL_RECOVERY_ENABLED`` to ``0`` / ``false``
    / ``no`` / ``off`` (case-insensitive) globally disables the
    recovery branch regardless of the ``recover`` parameter — useful
    for latency-sensitive workloads that cannot tolerate a ~45 s
    subprocess spawn on the agent path. Every call emits a structured
    "W-230 path:" log line documenting which branch ran (operator
    audit trail).

    Returns
    -------
    list[MailMessage]
        Primary pypff messages plus pffexport-recovered messages not
        already represented by the (subject, sender, date) dedup key.

        Recovered messages carry
        ``parser_note="pffexport_recovered:synthesized_eml:v{N}"``
        where ``v{N}`` is the pffexport version captured at recovery
        time (SIFT-W-231 audit trail; ``vunknown`` if the version
        probe failed). Downstream parsers should match the marker
        via ``startswith("pffexport_recovered:")`` to remain stable
        as more colon-separated tags are added.

        When recovery is *attempted* but fails (binary missing,
        timeout, subprocess error, no output dir), an extra deferral
        row with ``parser_note="pffexport_recovery_failed:{reason}"``
        is appended — silent log-only signaling would let forensic
        consumers miss the gap.
    """
    primary, skipped_errors = _parse_pst_impl(
        content, path, spill_attachment=spill_attachment,
    )

    # SIFT-W-230: kill switch wins over the `recover` parameter.
    if not _mail_recovery_enabled():
        logger.info(
            "W-230 path: pypff-only on %s (recovery disabled by %s=%r)",
            path,
            _MAIL_RECOVERY_ENABLED_ENV,
            os.environ.get(_MAIL_RECOVERY_ENABLED_ENV, ""),
        )
        return primary

    if recover == "off":
        logger.info("W-230 path: pypff-only on %s (recover=off)", path)
        return primary

    needs_recovery = (
        recover == "always"
        or any(_LOCAL_DESCRIPTORS_SIG in e for e in skipped_errors)
    )
    if not needs_recovery:
        logger.info(
            "W-230 path: pypff-only on %s (recover=%s, no local_descriptors skips)",
            path, recover,
        )
        return primary

    if not path.is_file():
        logger.warning(
            "W-230 path: pypff-only on %s (recovery requested but path is "
            "not a file on disk)", path,
        )
        return primary

    eff_timeout = timeout if timeout is not None else get_int(
        _PFF_RECOVERY_TIMEOUT_ENV, 300, floor=30, ceiling=1800,
    )
    fmt: MailFormat = "ost" if path.suffix.lower() == ".ost" else "pst"

    recovered, failure_reason = _pffexport_recover(
        path,
        timeout=eff_timeout,
        fmt=fmt,
        spill_attachment=spill_attachment,
    )
    if not recovered:
        if failure_reason is not None:
            # SIFT-W-231: recovery was attempted and failed — surface
            # the failure as an in-result deferral row so downstream
            # consumers don't silently miss the loss.
            logger.warning(
                "W-230 path: pypff-only on %s (recovery attempted, failed: %s)",
                path, failure_reason,
            )
            deferral = _pst_deferral(
                content, path, fmt,
                note=f"pffexport_recovery_failed:{failure_reason}",
            )
            return primary + [deferral]
        # No failure_reason → pffexport ran cleanly but found nothing
        # to recover. No deferral row needed; this is a real
        # "nothing to add" answer, not a chain-of-custody gap.
        logger.info(
            "W-230 path: pypff-only on %s (recovery attempted, "
            "pffexport returned no messages)", path,
        )
        return primary

    primary_keys = {_dedup_key(m) for m in primary if not m.parser_note}
    new_messages = [m for m in recovered if _dedup_key(m) not in primary_keys]
    # WARNING level (not INFO) because successful recovery is by
    # definition an exceptional code path — pypff failed for at least
    # one message, and we spawned an external binary to fill the gap.
    # Operators monitoring W-229 fallout want this surfaced.
    logger.warning(
        "W-230 path: auto-recovery on %s (+%d new messages; pypff kept %d, "
        "pffexport found %d total, %d deduped)",
        path, len(new_messages), len(primary), len(recovered),
        len(recovered) - len(new_messages),
    )
    return primary + new_messages


# --- MSG parser (W-219) ----------------------------------------------------


def parse_msg(
    content: bytes,
    path: Path,
    *,
    spill_attachment: Callable[[bytes, str], Path] | None = None,
) -> MailMessage:
    """Parse an Outlook ``.msg`` file via ``extract_msg``.

    On any ``extract_msg`` failure (including non-OLE2 input), returns a
    deferral ``MailMessage`` whose ``parser_note`` describes the cause.
    """
    has_magic = content.startswith(_OLE2_MAGIC)
    if not has_magic:
        return MailMessage(
            source_format="msg",
            source_path=str(path),
            parser_note="MSG header missing",
            detected_charset=None,
        )

    body_cap = get_int(_PFF_BODY_CHARS_ENV, 200_000, floor=128, ceiling=2_000_000)

    import extract_msg  # lazy import

    try:
        m = extract_msg.Message(str(path))
    except Exception as exc:  # extract_msg surfaces many error types
        logger.warning("extract_msg failed on %s: %s", path, exc)
        return MailMessage(
            source_format="msg",
            source_path=str(path),
            parser_note=f"extract_msg_failed: {exc!s}",
            detected_charset=None,
        )

    try:
        subject = str(m.subject or "")[:1024]
        sender = str(m.sender or "") or ""
        recipients: list[str] = []
        for r in (m.recipients or []):
            label = getattr(r, "email", None) or getattr(r, "name", None) or str(r)
            if label:
                recipients.append(str(label))
        date_attr = getattr(m, "date", None)
        date = date_attr.isoformat() if hasattr(date_attr, "isoformat") else str(date_attr or "")
        body_text = str(m.body or "")[:body_cap]

        attachments: list[Attachment] = []
        for idx, a in enumerate(m.attachments or []):
            att_bytes = getattr(a, "data", None) or b""
            if isinstance(att_bytes, str):
                att_bytes = att_bytes.encode("utf-8", errors="replace")
            fname = (
                getattr(a, "longFilename", None)
                or getattr(a, "shortFilename", None)
                or f"attachment_{idx}"
            )
            content_hash = (
                hashlib.sha256(att_bytes).hexdigest() if att_bytes else None
            )
            if spill_attachment and att_bytes:
                spill_attachment(att_bytes, fname)
            attachments.append(
                Attachment(
                    filename=fname,
                    mime_type=None,
                    size=len(att_bytes),
                    content_hash=content_hash,
                )
            )
    finally:
        with contextlib.suppress(Exception):
            m.close()

    return MailMessage(
        subject=subject,
        sender=sender,
        recipients=recipients,
        date=date,
        body_text=body_text,
        body_html=None,
        attachments=attachments,
        source_format="msg",
        source_path=str(path),
        parser_note="",
        detected_charset=None,
    )


# --- Deprecated stub-name aliases ------------------------------------------
#
# Pre-W-219 callers imported ``parse_pst_stub`` / ``parse_msg_stub``.
# Both names now alias the real parsers; the deprecated names will be
# removed in a follow-up once external callsites are updated.


def parse_pst_stub(content: bytes, path: Path) -> list[MailMessage]:
    """Deprecated: use :func:`parse_pst`. Kept for backward-compat imports."""
    return parse_pst(content, path)


def parse_msg_stub(content: bytes, path: Path) -> MailMessage:
    """Deprecated: use :func:`parse_msg`. Kept for backward-compat imports."""
    return parse_msg(content, path)
