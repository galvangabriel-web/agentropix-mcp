"""Maldoc analysis via python-oletools.

W-221: wraps the oletools triad (``olevba``, ``oleid``, ``rtfobj``)
behind a single Pydantic ``MacroReport`` so the SIFT mail-agent chain
can hand each attachment a tempfile path and receive a typed report of
macros, IOCs, obfuscation hints, and RTF-embedded objects.

Designed for the phishing-chain (W-219 PST/MSG extraction → this
wrapper → threat_intel + correlation). Phase 3 will wire the callsite
from ``MailAgent.investigate`` once PR #98 merges (R10 hard gate per
the phishing-chain implementation plan).

Tunables (``AGENTROPIX_*`` env vars, all clamped):

* ``AGENTROPIX_OLEVBA_TIMEOUT_S``   (float, default 120, [5, 3600])
* ``AGENTROPIX_OLEVBA_CODE_CHARS``  (int,   default 200_000, [128, 2_000_000])
* ``AGENTROPIX_OLEVBA_IOC_CAP``     (int,   default 500, [1, 10_000])
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from agentropix_mcp._env import get_float, get_int

logger = logging.getLogger(__name__)


_TIMEOUT_ENV = "AGENTROPIX_OLEVBA_TIMEOUT_S"
_CODE_CHARS_ENV = "AGENTROPIX_OLEVBA_CODE_CHARS"
_IOC_CAP_ENV = "AGENTROPIX_OLEVBA_IOC_CAP"

# File extensions the wrapper accepts. Anything else raises ValueError.
_ACCEPTED_SUFFIXES: frozenset[str] = frozenset({
    ".doc",  ".docm",  ".docx",  ".dotm",
    ".xls",  ".xlsm",  ".xlsx",  ".xlam",
    ".ppt",  ".pptm",  ".pptx",
    ".rtf",
    ".ole",
    ".bin",  # raw vbaProject.bin
})

# Obfuscation hint patterns — applied against decoded VBA source.
# Order matters only for the auto_exec category (we want the most
# specific match wins) but the overall hint set is unordered.
_HINT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("chr_concat",  re.compile(r"Chr\s*\(\s*\d+\s*\)\s*&", re.IGNORECASE)),
    ("base64_pwsh", re.compile(r"FromBase64String|powershell.*-enc", re.IGNORECASE)),
    ("str_reverse", re.compile(r"StrReverse\s*\(", re.IGNORECASE)),
    ("shellexec",   re.compile(r"WScript\.Shell|Shell\s*\(", re.IGNORECASE)),
    ("auto_exec",   re.compile(
        r"Auto_Open|Document_Open|Workbook_Open|InkPicture\w*_Painted",
        re.IGNORECASE,
    )),
    ("downloader",  re.compile(
        r"URLDownloadToFile|MSXML2\.XMLHTTP|WinHttp\.WinHttpRequest|XMLHTTP|WebClient",
        re.IGNORECASE,
    )),
)

# Auto-exec triggers — separate from the obfuscation set because
# downstream correlation cares about which exact trigger fired.
_AUTO_EXEC_TRIGGERS: tuple[str, ...] = (
    "Auto_Open", "AutoOpen", "Auto_Close", "AutoClose",
    "Document_Open", "DocumentOpen", "Document_Close", "DocumentClose",
    "Workbook_Open", "Workbook_Activate", "Workbook_BeforeClose",
    "Auto_Exec", "AutoExec",
    "InkPicture.Img_Painted", "InkPicture1_Painted",
)

# IOC regexes. Keep conservative — false-positive cost is high because
# the threat-intel layer will VT-lookup every emitted URL/IP.
_IOC_PATTERNS: dict[str, re.Pattern[str]] = {
    "url":  re.compile(
        r"https?://[^\s'\"<>`)]+",
        re.IGNORECASE,
    ),
    "ipv4": re.compile(
        r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])",
    ),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
}

# RTF Equation Editor object → CVE hint.
_EQUATION_CLASS_RE = re.compile(r"Equation\.\d+", re.IGNORECASE)


class MacroBlock(BaseModel):
    """A single decompressed VBA macro module."""

    stream_name: str = ""
    code: str = ""
    suspicious_keywords: list[str] = Field(default_factory=list)


class IoC(BaseModel):
    """One indicator-of-compromise mined from macro code / attachment data."""

    type: str  # "url" | "ipv4" | "ipv6" | "sha256" | "filename" | "cmdline"
    value: str
    source: str = ""  # e.g. "VBA/Module1" or "rtf_embedded_object"
    confidence: float = 0.7


class RtfObj(BaseModel):
    """One embedded OLE object carved from an RTF container."""

    class_name: str = ""
    sha256: str = ""
    size: int = 0
    cve_hint: str | None = None


class MacroReport(BaseModel):
    """Top-level olevba/oleid/rtfobj report for one file."""

    path: str
    sha256: str = ""
    file_type: str = ""  # e.g. "Word 2007+", "RTF", "OLE2"
    is_macro_enabled: bool = False
    auto_exec_candidates: list[str] = Field(default_factory=list)
    macros: list[MacroBlock] = Field(default_factory=list)
    iocs: list[IoC] = Field(default_factory=list)
    obfuscation_hints: list[str] = Field(default_factory=list)
    rtf_embedded_objects: list[RtfObj] = Field(default_factory=list)
    parser_note: str = ""
    tool: str = "oletools"


# --- Sync inner functions ---------------------------------------------------


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _file_type_via_oleid(path: Path) -> str:
    """Best-effort file-type identification via OleID indicators.

    Returns a short label ("Word 2007+", "RTF", "OLE2", "OOXML", "unknown")
    based on the indicators OleID exposes. Defensive against any
    indicator surface change in oletools.
    """
    suffix = path.suffix.lower()
    if suffix == ".rtf":
        return "RTF"
    try:
        from oletools.oleid import OleID  # lazy import
        oid = OleID(str(path))
        oid.check()
        ftype = oid.get_indicator("ftype")
        if ftype is not None:
            val = getattr(ftype, "value", None)
            if val:
                return str(val)
    except Exception as exc:  # noqa: BLE001
        logger.debug("oleid failed on %s: %s", path, exc)
    if suffix.endswith(("x", "xm", "tm")):
        return "OOXML"
    return "OLE2"


def _scan_obfuscation_hints(joined_code: str) -> list[str]:
    """Apply all `_HINT_PATTERNS` against a concatenation of VBA code."""
    hits: list[str] = []
    for name, pat in _HINT_PATTERNS:
        if pat.search(joined_code):
            hits.append(name)
    return hits


def _scan_auto_exec(joined_code: str) -> list[str]:
    """Return the auto-exec triggers found in the joined VBA source."""
    found: list[str] = []
    for trigger in _AUTO_EXEC_TRIGGERS:
        if (
            re.search(re.escape(trigger), joined_code, re.IGNORECASE)
            and trigger not in found
        ):
            found.append(trigger)
    return found


def _mine_iocs(text: str, *, source: str, cap: int) -> list[IoC]:
    """Mine URL/IPv4/sha256 indicators from a string.

    Conservative — IPv4 strict-3-octet form only; sha256 = 64-hex token
    on a word boundary. The cap fires across all types combined.
    """
    out: list[IoC] = []
    seen: set[tuple[str, str]] = set()
    for ioc_type, pat in _IOC_PATTERNS.items():
        for m in pat.finditer(text):
            value = m.group(0).rstrip(".,);:")
            key = (ioc_type, value)
            if key in seen:
                continue
            seen.add(key)
            out.append(IoC(type=ioc_type, value=value, source=source))
            if len(out) >= cap:
                return out
    return out


def _extract_macros_safe(vp: Any) -> list[tuple[str, str]]:
    """Pull (stream_name, vba_code) tuples from a VBA_Parser, defensively.

    ``VBA_Parser.extract_all_macros`` yields 4-tuples; the canonical
    shape is ``(filename, stream_path, vba_filename, vba_code)`` but the
    field order has shifted across oletools versions. We grab the last
    element as the code (always vba_code) and the second-to-last as a
    stream label.
    """
    out: list[tuple[str, str]] = []
    try:
        for entry in vp.extract_all_macros():
            if not entry:
                continue
            code = entry[-1] if entry[-1] else ""
            stream = entry[-2] if len(entry) >= 2 else ""
            if isinstance(code, bytes):
                code = code.decode("utf-8", errors="replace")
            if isinstance(stream, bytes):
                stream = stream.decode("utf-8", errors="replace")
            out.append((str(stream or ""), str(code or "")))
    except Exception as exc:  # noqa: BLE001
        logger.debug("extract_all_macros failed: %s", exc)
    return out


def _analyze_macros_safe(vp: Any) -> list[str]:
    """Return the keyword tokens olevba's analyze_macros produced.

    Tuple shape is ``(kind, keyword, description)``; we keep just the
    keyword as the "suspicious_keywords" entry. Returns ``[]`` on any
    failure.
    """
    keywords: list[str] = []
    try:
        results = vp.analyze_macros()
        for entry in results or []:
            if len(entry) >= 2:
                kw = entry[1]
                if isinstance(kw, bytes):
                    kw = kw.decode("utf-8", errors="replace")
                if kw:
                    keywords.append(str(kw))
    except Exception as exc:  # noqa: BLE001
        logger.debug("analyze_macros failed: %s", exc)
    return keywords


def _parse_rtf_objects(path: Path) -> list[RtfObj]:
    """Carve embedded OLE objects out of an RTF file via rtfobj."""
    objects: list[RtfObj] = []
    try:
        from oletools.rtfobj import RtfObjParser  # lazy
        data = path.read_bytes()
        rp = RtfObjParser(data)
        rp.parse()
        for obj in getattr(rp, "objects", []) or []:
            cls = getattr(obj, "class_name", "") or ""
            if isinstance(cls, bytes):
                cls = cls.decode("utf-8", errors="replace")
            raw = (
                getattr(obj, "oledata", None)
                or getattr(obj, "rawdata", None)
                or b""
            )
            if isinstance(raw, str):
                raw = raw.encode("utf-8", errors="replace")
            cve = "CVE-2017-11882" if _EQUATION_CLASS_RE.search(cls) else None
            objects.append(
                RtfObj(
                    class_name=cls,
                    sha256=hashlib.sha256(raw).hexdigest() if raw else "",
                    size=len(raw),
                    cve_hint=cve,
                )
            )
    except Exception as exc:  # noqa: BLE001
        logger.debug("rtfobj parse failed on %s: %s", path, exc)
    return objects


def _analyze_sync(path: Path, code_cap: int, ioc_cap: int) -> MacroReport:
    """Sync olevba/oleid/rtfobj analysis — invoked from a thread pool."""
    sha = _hash_file(path)
    file_type = _file_type_via_oleid(path)

    # RTF path: skip VBA parsing entirely, run rtfobj.
    if file_type == "RTF" or path.suffix.lower() == ".rtf":
        rtf_objs = _parse_rtf_objects(path)
        return MacroReport(
            path=str(path),
            sha256=sha,
            file_type="RTF",
            is_macro_enabled=False,
            rtf_embedded_objects=rtf_objs,
            parser_note="",
        )

    # OLE2 / OOXML path: VBA macro extraction.
    from oletools.olevba import VBA_Parser  # lazy import

    try:
        vp = VBA_Parser(str(path))
    except Exception as exc:  # noqa: BLE001
        logger.warning("VBA_Parser failed on %s: %s", path, exc)
        return MacroReport(
            path=str(path),
            sha256=sha,
            file_type=file_type,
            parser_note=f"vba_parser_failed: {exc!s}",
        )

    try:
        try:
            is_macro = bool(vp.detect_vba_macros())
        except Exception:  # noqa: BLE001
            is_macro = False

        macro_blocks: list[MacroBlock] = []
        joined_code = ""
        scanner_keywords: list[str] = []

        if is_macro:
            extracted = _extract_macros_safe(vp)
            scanner_keywords = _analyze_macros_safe(vp)
            for stream, code in extracted:
                truncated = code[:code_cap]
                macro_blocks.append(
                    MacroBlock(
                        stream_name=stream,
                        code=truncated,
                        suspicious_keywords=scanner_keywords,
                    )
                )
            joined_code = "\n".join(b.code for b in macro_blocks)

        obf_hints = _scan_obfuscation_hints(joined_code) if joined_code else []
        auto_exec = _scan_auto_exec(joined_code) if joined_code else []

        iocs: list[IoC] = []
        if joined_code:
            iocs = _mine_iocs(
                joined_code,
                source="vba_macros",
                cap=ioc_cap,
            )

        return MacroReport(
            path=str(path),
            sha256=sha,
            file_type=file_type,
            is_macro_enabled=is_macro,
            auto_exec_candidates=auto_exec,
            macros=macro_blocks,
            iocs=iocs,
            obfuscation_hints=obf_hints,
            rtf_embedded_objects=[],
            parser_note="",
        )
    finally:
        with contextlib.suppress(Exception):  # close is best-effort
            vp.close()


# --- Public async entry point ----------------------------------------------


async def analyze_maldoc(
    path: str | Path,
    *,
    timeout: float | None = None,
) -> MacroReport:
    """Analyse one Office / RTF document for malicious macro indicators.

    Parameters
    ----------
    path:
        File on disk. Must have one of the accepted suffixes (``.doc``,
        ``.docm``, ``.docx``, ``.dotm``, ``.xls``, ``.xlsm``, ``.xlsx``,
        ``.xlam``, ``.ppt``, ``.pptm``, ``.pptx``, ``.rtf``, ``.ole``,
        ``.bin``). Anything else raises ``ValueError`` — callers should
        not feed e.g. PDFs through this wrapper.
    timeout:
        Wall-clock cap in seconds. Defaults to
        ``AGENTROPIX_OLEVBA_TIMEOUT_S``. Raises ``asyncio.TimeoutError``
        if exceeded.

    Raises
    ------
    FileNotFoundError: target missing.
    ValueError: file suffix not in the accepted set.
    asyncio.TimeoutError: oletools exceeded the timeout.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Maldoc target not found: {p}")
    if p.suffix.lower() not in _ACCEPTED_SUFFIXES:
        raise ValueError(
            f"Unsupported maldoc suffix {p.suffix!r}; expected one of "
            f"{sorted(_ACCEPTED_SUFFIXES)}"
        )

    timeout_s = timeout if timeout is not None else get_float(
        _TIMEOUT_ENV, 120.0, floor=5.0, ceiling=3600.0
    )
    code_cap = get_int(_CODE_CHARS_ENV, 200_000, floor=128, ceiling=2_000_000)
    ioc_cap = get_int(_IOC_CAP_ENV, 500, floor=1, ceiling=10_000)

    loop = asyncio.get_running_loop()
    return await asyncio.wait_for(
        loop.run_in_executor(None, _analyze_sync, p, code_cap, ioc_cap),
        timeout=timeout_s,
    )
