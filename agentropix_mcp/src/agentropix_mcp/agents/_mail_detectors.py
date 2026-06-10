"""T1566 (Phishing) detectors for the MailAgent (issue #17).

Pure functions over a list of :class:`MailMessage` (no I/O, no MCP
coupling). Each detector returns ``list[Finding]``; the agent layer
combines them. Each finding's ``mitre_attack`` field carries the
specific T1566 sub-technique:

* :func:`detect_dangerous_attachments` -> ``T1566.001`` (executable
  attachments: ``.exe``, ``.scr``, ``.lnk``, ``.iso``, ``.cab``, ``.bat``,
  ``.cmd``, ``.vbs``, ``.js``, ``.wsf``, ``.hta``)
* :func:`detect_macro_documents` -> ``T1566.001`` (macro-enabled Office:
  ``.docm``, ``.xlsm``, ``.pptm``, ``.dotm``)
* :func:`detect_link_mismatch` -> ``T1566.002`` (anchor-text / href
  domain mismatch)
* :func:`detect_oauth_phish` -> ``T1566.003`` (OAuth consent URL with
  attacker-controlled ``redirect_uri``)
* :func:`detect_lookalike_sender` -> ``T1566`` (lookalike sender domain
  within edit-distance ``<=`` configured floor of a high-value brand)
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit

from agentropix_mcp.agents._base import Finding
from agentropix_mcp.agents._mail_parsers import MailMessage

_T1566 = "T1566"
_T1566_001 = "T1566.001"
_T1566_002 = "T1566.002"
_T1566_003 = "T1566.003"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


_DANGEROUS_EXTS: frozenset[str] = frozenset(
    {
        ".exe",
        ".scr",
        ".lnk",
        ".iso",
        ".cab",
        ".bat",
        ".cmd",
        ".vbs",
        ".js",
        ".wsf",
        ".hta",
    }
)

_MACRO_EXTS: frozenset[str] = frozenset({".docm", ".xlsm", ".pptm", ".dotm"})


def _hash_evidence(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8", errors="replace"))
        h.update(b"\x00")
    return h.hexdigest()


def _attachment_ext(filename: str) -> str:
    if not filename or "." not in filename:
        return ""
    return "." + filename.rsplit(".", 1)[1].lower()


_ANGLE_ADDR_RE = re.compile(r"<([^<>]+@[^<>]+)>")


def _extract_address(value: str) -> str:
    """Pull the bare ``user@host`` from a header that may include a name.

    Examples:
      ``"Alice <alice@x.com>"`` -> ``"alice@x.com"``
      ``"alice@x.com"``         -> ``"alice@x.com"``
    """
    if not value:
        return ""
    m = _ANGLE_ADDR_RE.search(value)
    if m:
        return m.group(1).strip()
    return value.strip()


def _domain_of(address: str) -> str:
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].strip().lower().rstrip(">")


def _registrable_domain(host: str) -> str:
    """Return the last two labels of ``host`` lower-cased.

    Not a real PSL lookup — good enough for distinguishing
    ``login.microsoft.com`` from ``login.microsoftonline.com.attacker.tld``
    without dragging in the ``publicsuffix2`` package.
    """
    if not host:
        return ""
    host = host.strip().lower().rstrip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])


# ---------------------------------------------------------------------------
# T1566.001 — dangerous attachments
# ---------------------------------------------------------------------------


def detect_dangerous_attachments(messages: Iterable[MailMessage]) -> list[Finding]:
    """Flag messages whose attachments include a dangerous executable
    extension (``.exe``, ``.scr``, ``.lnk``, ``.iso``, ``.cab``, ``.bat``,
    ``.cmd``, ``.vbs``, ``.js``, ``.wsf``, ``.hta``).

    One Finding per (message, attachment) pair so the timeline keeps the
    file-level granularity needed for IOC pivots.
    """
    out: list[Finding] = []
    for msg in messages:
        if not msg.attachments:
            continue
        for att in msg.attachments:
            ext = _attachment_ext(att.filename)
            if ext not in _DANGEROUS_EXTS:
                continue
            sender_addr = _extract_address(msg.sender)
            payload_hash = _hash_evidence(att.filename, sender_addr, msg.subject)
            out.append(
                Finding(
                    source="mail.dangerous_attachment",
                    confidence=0.85,
                    description=(
                        f"[T1566.001] Executable attachment '{att.filename}' "
                        f"({ext}) from {sender_addr or 'unknown'}"
                    ),
                    evidence=(
                        f"sender={sender_addr} subject={msg.subject[:160]}"
                        f" attachment={att.filename} size={att.size}"
                        f" mime={att.mime_type or 'unknown'}"
                    ),
                    evidence_dict={
                        "sender": sender_addr,
                        "subject": msg.subject,
                        "attachment_filename": att.filename,
                        "attachment_extension": ext,
                        "attachment_size": att.size,
                        "attachment_mime": att.mime_type or "",
                        "attachment_sha256": att.content_hash or "",
                        "source_format": msg.source_format,
                        "payload_hash": payload_hash,
                    },
                    mitre_attack=_T1566_001,
                    timestamp=msg.date or Finding.now(),
                )
            )
    return out


# ---------------------------------------------------------------------------
# T1566.001 — macro-enabled documents
# ---------------------------------------------------------------------------


def detect_macro_documents(messages: Iterable[MailMessage]) -> list[Finding]:
    """Flag attachments with macro-enabled Office extensions.

    Not as strong a signal as a raw ``.exe`` (legitimate templates exist),
    so confidence is lower (0.6) than :func:`detect_dangerous_attachments`.
    """
    out: list[Finding] = []
    for msg in messages:
        for att in msg.attachments:
            ext = _attachment_ext(att.filename)
            if ext not in _MACRO_EXTS:
                continue
            sender_addr = _extract_address(msg.sender)
            payload_hash = _hash_evidence(att.filename, sender_addr, msg.subject)
            out.append(
                Finding(
                    source="mail.macro_document",
                    confidence=0.6,
                    description=(
                        f"[T1566.001] Macro-enabled document '{att.filename}' "
                        f"({ext}) from {sender_addr or 'unknown'}"
                    ),
                    evidence=(
                        f"sender={sender_addr} subject={msg.subject[:160]}"
                        f" attachment={att.filename} size={att.size}"
                    ),
                    evidence_dict={
                        "sender": sender_addr,
                        "subject": msg.subject,
                        "attachment_filename": att.filename,
                        "attachment_extension": ext,
                        "attachment_size": att.size,
                        "attachment_mime": att.mime_type or "",
                        "attachment_sha256": att.content_hash or "",
                        "source_format": msg.source_format,
                        "payload_hash": payload_hash,
                    },
                    mitre_attack=_T1566_001,
                    timestamp=msg.date or Finding.now(),
                )
            )
    return out


# ---------------------------------------------------------------------------
# T1566.002 — link mismatch in HTML body
# ---------------------------------------------------------------------------


_URL_LIKE_RE = re.compile(r"\b(?:https?://)?([a-z0-9.-]+\.[a-z]{2,})", re.IGNORECASE)


class _AnchorCollector(HTMLParser):
    """Collect ``(href, text)`` tuples from each ``<a>`` element."""

    def __init__(self) -> None:
        super().__init__()
        self.anchors: list[tuple[str, str]] = []
        self._href: str | None = None
        self._buffer: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        href = ""
        for k, v in attrs:
            if k.lower() == "href" and v:
                href = v
                break
        self._href = href
        self._buffer = []

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "a" or self._href is None:
            return
        text = "".join(self._buffer).strip()
        self.anchors.append((self._href, text))
        self._href = None
        self._buffer = []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._buffer.append(data)


def _anchor_text_domain(text: str) -> str:
    """Pick the most-likely domain mentioned in anchor text, lower-cased."""
    if not text:
        return ""
    m = _URL_LIKE_RE.search(text)
    if not m:
        return ""
    return m.group(1).strip().lower()


def detect_link_mismatch(messages: Iterable[MailMessage]) -> list[Finding]:
    """Flag HTML anchors whose visible text references one domain but
    whose href points to a different one.

    Heuristic: anchor text contains a URL-like fragment (``foo.com``) and
    the href targets a different registrable domain. Mailto: hrefs and
    in-document anchors (``#section``) are ignored.
    """
    out: list[Finding] = []
    for msg in messages:
        if not msg.body_html:
            continue
        parser = _AnchorCollector()
        try:
            parser.feed(msg.body_html)
        except Exception:
            continue
        for href, text in parser.anchors:
            if not href:
                continue
            href_lower = href.strip().lower()
            if href_lower.startswith(("mailto:", "tel:", "#", "javascript:")):
                continue
            href_host = _registrable_domain(urlsplit(href_lower).hostname or "")
            if not href_host:
                continue
            text_host = _registrable_domain(_anchor_text_domain(text))
            if not text_host:
                continue
            if text_host == href_host:
                continue
            sender_addr = _extract_address(msg.sender)
            payload_hash = _hash_evidence(href, text, sender_addr)
            out.append(
                Finding(
                    source="mail.link_mismatch",
                    confidence=0.75,
                    description=(
                        f"[T1566.002] Anchor text '{text[:80]}' references "
                        f"{text_host} but href targets {href_host}"
                    ),
                    evidence=(
                        f"sender={sender_addr} subject={msg.subject[:160]}"
                        f" anchor_text={text[:160]} href={href[:240]}"
                    ),
                    evidence_dict={
                        "sender": sender_addr,
                        "subject": msg.subject,
                        "anchor_text": text,
                        "anchor_text_domain": text_host,
                        "href": href,
                        "href_domain": href_host,
                        "source_format": msg.source_format,
                        "payload_hash": payload_hash,
                    },
                    mitre_attack=_T1566_002,
                    timestamp=msg.date or Finding.now(),
                )
            )
    return out


# ---------------------------------------------------------------------------
# T1566.003 — OAuth consent phishing
# ---------------------------------------------------------------------------


_OAUTH_HOST_DOMAINS: tuple[tuple[str, str], ...] = (
    # (consent_host_domain, expected_redirect_root_domain)
    ("login.microsoftonline.com", "microsoft.com"),
    ("login.microsoft.com", "microsoft.com"),
    ("accounts.google.com", "google.com"),
    ("oauth.googleapis.com", "google.com"),
)

_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def _safe_redirect_for(consent_host: str) -> tuple[str, ...]:
    """Return the registrable-domain whitelist for a given consent host."""
    for host, expected in _OAUTH_HOST_DOMAINS:
        if consent_host.endswith(host):
            return (expected,)
    return ()


def _iter_urls_from_message(msg: MailMessage) -> Iterable[str]:
    if msg.body_html:
        # Anchor href values first.
        parser = _AnchorCollector()
        try:
            parser.feed(msg.body_html)
        except Exception:
            parser.anchors = []
        for href, _ in parser.anchors:
            if href:
                yield href
        # Plain URLs that appear as raw text inside the HTML.
        for m in _URL_RE.finditer(msg.body_html):
            yield m.group(0)
    if msg.body_text:
        for m in _URL_RE.finditer(msg.body_text):
            yield m.group(0)


def detect_oauth_phish(messages: Iterable[MailMessage]) -> list[Finding]:
    """Flag OAuth consent URLs whose ``redirect_uri`` parameter points to
    a domain outside the expected provider's registrable domain.

    Provider hosts covered: Microsoft (``login.microsoftonline.com``,
    ``login.microsoft.com``) and Google (``accounts.google.com``,
    ``oauth.googleapis.com``). A redirect targeting the same provider's
    domain is treated as legitimate and not flagged.
    """
    out: list[Finding] = []
    for msg in messages:
        seen: set[str] = set()
        for url in _iter_urls_from_message(msg):
            if url in seen:
                continue
            seen.add(url)
            try:
                parts = urlsplit(url)
            except ValueError:
                continue
            host = (parts.hostname or "").lower()
            allowed = _safe_redirect_for(host)
            if not allowed:
                continue
            qs = parse_qs(parts.query)
            redirect = (
                qs.get("redirect_uri")
                or qs.get("redirect-uri")
                or qs.get("returnUrl")
                or qs.get("return_to")
                or []
            )
            if not redirect:
                continue
            redirect_url = redirect[0]
            redirect_host = (urlsplit(redirect_url).hostname or "").lower()
            redirect_root = _registrable_domain(redirect_host)
            if not redirect_root:
                continue
            if any(redirect_root == expected or redirect_host.endswith("." + expected) for expected in allowed):
                continue
            sender_addr = _extract_address(msg.sender)
            payload_hash = _hash_evidence(url, redirect_url, sender_addr)
            out.append(
                Finding(
                    source="mail.oauth_phish",
                    confidence=0.85,
                    description=(
                        f"[T1566.003] OAuth consent URL on {host} with "
                        f"redirect_uri pointing to attacker-controlled "
                        f"{redirect_root}"
                    ),
                    evidence=(
                        f"sender={sender_addr} subject={msg.subject[:160]}"
                        f" consent_url={url[:240]} redirect_uri={redirect_url[:240]}"
                    ),
                    evidence_dict={
                        "sender": sender_addr,
                        "subject": msg.subject,
                        "consent_url": url,
                        "consent_host": host,
                        "redirect_uri": redirect_url,
                        "redirect_host": redirect_host,
                        "expected_domains": list(allowed),
                        "source_format": msg.source_format,
                        "payload_hash": payload_hash,
                    },
                    mitre_attack=_T1566_003,
                    timestamp=msg.date or Finding.now(),
                )
            )
    return out


# ---------------------------------------------------------------------------
# T1566 — lookalike sender domain
# ---------------------------------------------------------------------------


_LOOKALIKE_TARGETS: tuple[str, ...] = (
    "microsoft.com",
    "google.com",
    "paypal.com",
    "amazon.com",
    "apple.com",
    "office.com",
    "outlook.com",
)


def _levenshtein(a: str, b: str) -> int:
    """Iterative Levenshtein distance — no deps.

    Two-row DP, ``O(len(a)*len(b))`` time / ``O(min(a,b))`` space. Used
    for short domain strings so the constant factor is irrelevant.
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            current[j] = min(
                previous[j] + 1,         # deletion
                current[j - 1] + 1,      # insertion
                previous[j - 1] + cost,  # substitution
            )
        previous = current
    return previous[-1]


def detect_lookalike_sender(
    messages: Iterable[MailMessage],
    *,
    distance_floor: int = 2,
    targets: tuple[str, ...] = _LOOKALIKE_TARGETS,
) -> list[Finding]:
    """Flag senders whose registrable domain is within ``distance_floor``
    edit-operations of a high-value target but is not an exact match.

    Hits with distance ``0`` are legitimate senders and never fire. Hits
    with distance ``1`` or ``2`` are flagged. The target list is
    intentionally small — extending it to thousands of brand names risks
    false positives without coverage gain in the SANS use-case.
    """
    if distance_floor < 1:
        return []
    out: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for msg in messages:
        sender_addr = _extract_address(msg.sender)
        sender_domain = _domain_of(sender_addr)
        if not sender_domain:
            continue
        registrable = _registrable_domain(sender_domain)
        if not registrable:
            continue
        for target in targets:
            distance = _levenshtein(registrable, target)
            if distance == 0 or distance > distance_floor:
                continue
            key = (registrable, target)
            if key in seen:
                continue
            seen.add(key)
            payload_hash = _hash_evidence(sender_addr, target, str(distance))
            out.append(
                Finding(
                    source="mail.lookalike_sender",
                    confidence=0.7,
                    description=(
                        f"[T1566] Sender domain '{registrable}' looks like "
                        f"'{target}' (edit distance {distance})"
                    ),
                    evidence=(
                        f"sender={sender_addr} sender_domain={registrable}"
                        f" target={target} distance={distance}"
                        f" subject={msg.subject[:160]}"
                    ),
                    evidence_dict={
                        "sender": sender_addr,
                        "sender_domain": registrable,
                        "target_domain": target,
                        "edit_distance": distance,
                        "subject": msg.subject,
                        "source_format": msg.source_format,
                        "payload_hash": payload_hash,
                    },
                    mitre_attack=_T1566,
                    timestamp=msg.date or Finding.now(),
                )
            )
            break  # don't fire multiple lookalike findings per message
    return out


# ---------------------------------------------------------------------------
# T1566 — SPF/DKIM/DMARC authentication failure
# ---------------------------------------------------------------------------


def detect_auth_failure(messages: list[dict]) -> list[Finding]:
    """Detect T1566 spoofed sender from email authentication failures.

    Takes the ``messages`` list returned by
    :func:`~agentropix_mcp.wrappers.email_headers.email_header_matrix`.
    Fires when DMARC fails AND at least one of SPF or DKIM also fails —
    the combination strongly indicates a domain spoofing attempt.

    Args:
        messages: List of header-matrix record dicts, each carrying
            ``spf``, ``dkim``, ``dmarc``, ``from_email``, and ``path``.

    Returns:
        List of T1566 Findings, one per authentication-failing message.
    """
    out: list[Finding] = []
    for rec in messages:
        spf = (rec.get("spf") or "none").lower()
        dkim = (rec.get("dkim") or "none").lower()
        dmarc = (rec.get("dmarc") or "none").lower()

        spf_fail = spf in ("fail", "softfail")
        dkim_fail = dkim == "fail"
        dmarc_fail = dmarc == "fail"

        if not dmarc_fail or not (spf_fail or dkim_fail):
            continue

        from_email = rec.get("from_email", "")
        path = rec.get("path", "")
        auth_summary = f"spf={spf} dkim={dkim} dmarc={dmarc}"

        out.append(
            Finding(
                source="mail.auth_failure",
                confidence=0.85,
                description=(
                    f"[T1566] Authentication failure for mail from {from_email}: "
                    f"{auth_summary}"
                ),
                evidence=f"path={path} from={from_email} {auth_summary}",
                evidence_dict={
                    "source_path": path,
                    "from_email": from_email,
                    "spf": spf,
                    "dkim": dkim,
                    "dmarc": dmarc,
                },
                mitre_attack=_T1566,
                timestamp=Finding.now(),
            )
        )
    return out
