"""W-103 — PDF text-extraction wrapper for the MCP boundary.

Converts the threat-intel corpus from "indicator extraction" (raw IOC
regex via ``bulk_extractor`` / ``run_strings``) into "knowledge
extraction": a single ``pdf_extract_text(target=..., pages="14")`` call
returns text + page provenance + document metadata, ready to feed
downstream NER / CVE / FTS-index tooling.

Engine matrix (fall-through order):
    pdftotext (poppler-utils) → primary; ships with SANS SIFT, supports
        per-page selection via ``-f N -l N``, returns plain text on
        stdout, and is by far the fastest extractor on real CTI PDFs.

The draft spec (``docs/mcp-gap-analysis/drafts/pdf_extract_text.md``)
proposed pymupdf as the preferred engine. We deliberately diverge here
because the SIFT operator workflow already has poppler installed and a
pure-subprocess engine keeps the wrapper free of new Python deps. The
``engine`` field on the result is retained as a forward-compatibility
hook — when pypdf / pdfminer become installable in the runtime they
plug in behind the same model.

OCR mode is *out of scope* for this iteration. The draft spec carves
it out as a separate ``ocr=True`` path; not implementing it keeps the
wrapper small. A future ``run_ocr`` MCP tool can compose with this one
when an operator hands SIFT a scanned-only PDF.

Resource limits:
    - ``AGENTROPIX_PDF_MAX_BYTES``        (default 200 MiB) — hard cap
      on input file size. pdftotext memory scales with page complexity
      so we refuse oversized PDFs at the wrapper before opening.
    - ``AGENTROPIX_PDF_MAX_PAGES``        (default 1000) — cap on
      pages extracted per call. Pages above the cap surface in
      ``skipped_pages``.
    - ``AGENTROPIX_PDF_MAX_CHARS``        (default 200 000) — cap on
      per-page text bytes. Truncation surfaces on the per-page row
      (``truncated=True``) AND on the document-level rollup.
    - ``AGENTROPIX_PDF_EXTRACT_TIMEOUT``  (default 180 s, floor 5,
      ceiling 3600) — wall-clock cap on each per-page subprocess.

Chain-of-custody (SIFT-W-082):
    The SHA-256 of the source PDF bytes is computed BEFORE any
    extraction subprocess runs. The ``raw_stdout_sha256`` field is the
    digest of ``"\\n\\f".join(p.text)`` so two re-extractions can be
    compared byte-exact.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import shutil
import time
from pathlib import Path

from agentropix_mcp._env import clamp_float, get_float, get_int
from agentropix_mcp.wrappers._subprocess import run_with_memory_limit
from agentropix_mcp.schema.pdf_extract_text import PdfDocument, PdfPage

logger = logging.getLogger(__name__)

DEFAULT_PDFTOTEXT = "pdftotext"
DEFAULT_PDFINFO = "pdfinfo"

_DEFAULT_MAX_BYTES = 200 * 1024 * 1024  # 200 MiB
_DEFAULT_MAX_PAGES = 1000
_DEFAULT_MAX_CHARS = 200_000
_DEFAULT_TIMEOUT = 180.0
_TIMEOUT_FLOOR = 5.0
_TIMEOUT_CEILING = 3600.0

# 64 KiB hash chunk — same constant other wrappers use.
_CHUNK = 64 * 1024


def _resolve_pdftotext() -> str:
    return os.environ.get("AGENTROPIX_PDFTOTEXT_TOOL", DEFAULT_PDFTOTEXT)


def _resolve_pdfinfo() -> str:
    return os.environ.get("AGENTROPIX_PDFINFO_TOOL", DEFAULT_PDFINFO)


def parse_page_spec(spec: str | None, page_count: int) -> list[int]:
    """Expand a ``"1-5,12,20-"`` style spec into a sorted unique page list.

    Grammar (commas split tokens; each token is one of):
        ``N``       single page (1-indexed).
        ``N-M``     inclusive range, ``N <= M``.
        ``N-``      ``N`` through end-of-document.
        ``-M``      page 1 through ``M``.

    Returns the empty list when ``spec`` is ``None`` or empty (the
    caller treats that as "all pages"). Raises ``ValueError`` on any
    unparseable token, out-of-range page, or negative number — the
    wrapper surfaces this as a top-level error rather than silently
    skipping bad tokens, so an operator typo can't quietly truncate
    the extraction.
    """
    if spec is None or not spec.strip():
        return list(range(1, page_count + 1))

    out: set[int] = set()
    for raw_token in spec.split(","):
        token = raw_token.strip()
        if not token:
            continue
        if "-" in token:
            lo_raw, hi_raw = token.split("-", 1)
            lo_raw = lo_raw.strip()
            hi_raw = hi_raw.strip()
            try:
                lo = int(lo_raw) if lo_raw else 1
                hi = int(hi_raw) if hi_raw else page_count
            except ValueError as exc:
                raise ValueError(f"unparseable page-range token {token!r}") from exc
            if lo < 1 or hi < 1 or lo > hi:
                raise ValueError(f"invalid page range {token!r}")
            if hi > page_count:
                hi = page_count
            if lo > page_count:
                continue
            out.update(range(lo, hi + 1))
        else:
            try:
                n = int(token)
            except ValueError as exc:
                raise ValueError(f"unparseable page token {token!r}") from exc
            if n < 1:
                raise ValueError(f"invalid page number {n}")
            if n <= page_count:
                out.add(n)
    return sorted(out)


_PDFINFO_PAGES_RE = re.compile(r"^Pages:\s+(\d+)\s*$", re.MULTILINE)
_PDFINFO_TITLE_RE = re.compile(r"^Title:\s+(.*?)\s*$", re.MULTILINE)
_PDFINFO_AUTHOR_RE = re.compile(r"^Author:\s+(.*?)\s*$", re.MULTILINE)
_PDFINFO_CREATED_RE = re.compile(r"^CreationDate:\s+(.*?)\s*$", re.MULTILINE)
_PDFINFO_ENCRYPTED_RE = re.compile(r"^Encrypted:\s+(.*?)\s*$", re.MULTILINE)


def _parse_pdfinfo(stdout: str) -> dict[str, object]:
    """Parse ``pdfinfo`` stdout into the subset of fields we need."""
    pages_m = _PDFINFO_PAGES_RE.search(stdout)
    title_m = _PDFINFO_TITLE_RE.search(stdout)
    author_m = _PDFINFO_AUTHOR_RE.search(stdout)
    created_m = _PDFINFO_CREATED_RE.search(stdout)
    enc_m = _PDFINFO_ENCRYPTED_RE.search(stdout)
    return {
        "page_count": int(pages_m.group(1)) if pages_m else 0,
        "title": title_m.group(1) if title_m else "",
        "author": author_m.group(1) if author_m else "",
        "created": created_m.group(1) if created_m else "",
        "encrypted": (enc_m.group(1) if enc_m else "no").lower(),
    }


async def _kill_and_reap(proc: asyncio.subprocess.Process) -> None:
    """Kill a subprocess and reap the zombie within a bounded budget.

    Mirrors ``extract_archive::_kill_and_reap``. Without it a wedged
    pdftotext could hold the asyncio transport open and amplify a
    per-page timeout into a server-wide stall.
    """
    if proc.returncode is None:
        proc.kill()
    try:
        await asyncio.wait_for(proc.wait(), timeout=2.0)
    except (TimeoutError, ProcessLookupError):
        pass


async def _run_pdfinfo(pdf: Path, timeout: float) -> tuple[str, str]:
    """Run ``pdfinfo <pdf>`` and return ``(stdout, stderr)``."""
    binary = shutil.which(_resolve_pdfinfo())
    if binary is None:
        raise FileNotFoundError(
            "pdfinfo not found on PATH — install poppler-utils or set "
            "AGENTROPIX_PDFINFO_TOOL"
        )
    cmd = [binary, "--", str(pdf)]
    logger.info("Running: %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_bytes, stderr_bytes = await run_with_memory_limit(
            proc, timeout, "pdf-pdfinfo"
        )
    except TimeoutError:
        await _kill_and_reap(proc)
        raise TimeoutError(f"pdfinfo timed out after {timeout}s") from None
    if proc.returncode != 0:
        # pdfinfo exits non-zero on encrypted/corrupt PDFs; surface
        # stderr so the caller can map to a meaningful error.
        raise RuntimeError(
            f"pdfinfo failed (rc={proc.returncode}): "
            f"{stderr_bytes.decode(errors='replace')[:300]}"
        )
    return (
        stdout_bytes.decode(errors="replace"),
        stderr_bytes.decode(errors="replace"),
    )


async def _run_pdftotext_page(
    pdf: Path,
    page: int,
    *,
    timeout: float,
) -> tuple[str, str]:
    """Run ``pdftotext -f N -l N <pdf> -`` and return ``(stdout, stderr)``."""
    binary = shutil.which(_resolve_pdftotext())
    if binary is None:
        raise FileNotFoundError(
            "pdftotext not found on PATH — install poppler-utils or "
            "set AGENTROPIX_PDFTOTEXT_TOOL"
        )
    cmd = [binary, "-f", str(page), "-l", str(page), "--", str(pdf), "-"]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_bytes, stderr_bytes = await run_with_memory_limit(
            proc, timeout, "pdf-pdftotext"
        )
    except TimeoutError:
        await _kill_and_reap(proc)
        raise TimeoutError(
            f"pdftotext page {page} timed out after {timeout}s"
        ) from None
    if proc.returncode != 0:
        raise RuntimeError(
            f"pdftotext page {page} failed (rc={proc.returncode}): "
            f"{stderr_bytes.decode(errors='replace')[:300]}"
        )
    return (
        stdout_bytes.decode(errors="replace"),
        stderr_bytes.decode(errors="replace"),
    )


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


async def _capture_engine_version(timeout: float = 5.0) -> str:
    """Run ``pdftotext -v`` once to surface the engine build string."""
    binary = shutil.which(_resolve_pdftotext())
    if binary is None:
        return ""
    proc = await asyncio.create_subprocess_exec(
        binary,
        "-v",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        # pdftotext -v writes to stderr.
        _, stderr_bytes = await run_with_memory_limit(
            proc, timeout, "pdf-pdftotext-version"
        )
    except TimeoutError:
        await _kill_and_reap(proc)
        return ""
    text = stderr_bytes.decode(errors="replace").strip()
    return text.splitlines()[0] if text else ""


async def pdf_extract_text(
    target: str | Path,
    *,
    pages: str | None = None,
    max_pages: int | None = None,
    max_chars: int | None = None,
    timeout: float | None = None,
) -> PdfDocument:
    """Extract per-page text from a PDF and return a typed ``PdfDocument``.

    Args:
        target: Path to a PDF file.
        pages: Page-range spec (``"1-5,12,20-"``). ``None`` extracts
            every page subject to the ``max_pages`` cap.
        max_pages: Override ``AGENTROPIX_PDF_MAX_PAGES`` (default 1000,
            floor 1, ceiling 100_000).
        max_chars: Per-page text cap. Override
            ``AGENTROPIX_PDF_MAX_CHARS`` (default 200_000, floor 100,
            ceiling 100_000_000).
        timeout: Per-page subprocess timeout in seconds. ``None``
            (default) reads ``AGENTROPIX_PDF_EXTRACT_TIMEOUT`` (180 s,
            floor 5, ceiling 3600). Explicit overrides are clamped to
            the same window.

    Raises:
        FileNotFoundError: target missing or pdftotext / pdfinfo not on
            PATH.
        ValueError: target is not a regular file, oversize per
            ``AGENTROPIX_PDF_MAX_BYTES``, or the page-range spec
            unparseable.
        RuntimeError: pdfinfo reports the PDF is encrypted /
            password-protected, or pdftotext fails on every requested
            page.
        TimeoutError: pdfinfo or pdftotext exceeded ``timeout``.
    """
    started = time.monotonic()

    pdf_path = Path(target)
    if not pdf_path.exists():
        raise FileNotFoundError(f"PDF not found: {pdf_path}")
    if not pdf_path.is_file():
        raise ValueError(f"PDF target is not a regular file: {pdf_path}")

    max_bytes_cap = get_int(
        "AGENTROPIX_PDF_MAX_BYTES",
        _DEFAULT_MAX_BYTES,
        floor=1024,
        ceiling=2**62,
    )
    file_size = pdf_path.stat().st_size
    if file_size > max_bytes_cap:
        raise ValueError(
            f"PDF too large: {file_size} bytes > "
            f"AGENTROPIX_PDF_MAX_BYTES={max_bytes_cap}"
        )

    if max_pages is None:
        max_pages = get_int(
            "AGENTROPIX_PDF_MAX_PAGES",
            _DEFAULT_MAX_PAGES,
            floor=1,
            ceiling=100_000,
        )
    else:
        max_pages = max(1, min(int(max_pages), 100_000))

    if max_chars is None:
        max_chars = get_int(
            "AGENTROPIX_PDF_MAX_CHARS",
            _DEFAULT_MAX_CHARS,
            floor=100,
            ceiling=100_000_000,
        )
    else:
        max_chars = max(100, min(int(max_chars), 100_000_000))

    if timeout is None:
        timeout = get_float(
            "AGENTROPIX_PDF_EXTRACT_TIMEOUT",
            _DEFAULT_TIMEOUT,
            floor=_TIMEOUT_FLOOR,
            ceiling=_TIMEOUT_CEILING,
        )
    else:
        timeout = clamp_float(
            "AGENTROPIX_PDF_EXTRACT_TIMEOUT",
            float(timeout),
            floor=_TIMEOUT_FLOOR,
            ceiling=_TIMEOUT_CEILING,
        )

    pdf_sha256 = _hash_file(pdf_path)

    info_stdout, info_stderr = await _run_pdfinfo(pdf_path, timeout=timeout)
    info = _parse_pdfinfo(info_stdout)
    page_count = int(info["page_count"])
    if info["encrypted"] not in ("no", ""):
        raise RuntimeError(
            f"PDF encrypted/password-protected: {pdf_path} "
            f"(pdfinfo Encrypted: {info['encrypted']!r})"
        )
    if page_count <= 0:
        raise RuntimeError(
            f"pdfinfo reported 0 pages for {pdf_path} — corrupt PDF?"
        )

    requested = parse_page_spec(pages, page_count)

    # Apply max_pages cap. skipped_pages preserves the cap-victim list.
    selected = requested[:max_pages]
    skipped = requested[max_pages:]

    engine_version = await _capture_engine_version()

    page_rows: list[PdfPage] = []
    stderr_chunks: list[str] = [info_stderr] if info_stderr else []
    any_truncation = False

    for page_no in selected:
        try:
            stdout, stderr = await _run_pdftotext_page(
                pdf_path, page_no, timeout=timeout
            )
        except TimeoutError as exc:
            page_rows.append(
                PdfPage(
                    page=page_no,
                    ok=False,
                    error=f"timeout: {exc}",
                )
            )
            continue
        except RuntimeError as exc:
            page_rows.append(
                PdfPage(
                    page=page_no,
                    ok=False,
                    error=f"render failure: {exc}",
                )
            )
            continue

        if stderr:
            stderr_chunks.append(stderr)

        truncated = len(stdout) > max_chars
        if truncated:
            stdout = stdout[:max_chars]
            any_truncation = True
        page_rows.append(
            PdfPage(
                page=page_no,
                ok=True,
                error="",
                text=stdout,
                char_count=len(stdout),
                truncated=truncated,
            )
        )

    combined_stderr = ("\n".join(s for s in stderr_chunks if s))[:1000]
    rollup_text = "\n\f".join(p.text for p in page_rows)
    rollup_sha256 = hashlib.sha256(rollup_text.encode("utf-8")).hexdigest()

    duration_ms = (time.monotonic() - started) * 1000.0

    return PdfDocument(
        target=str(pdf_path.resolve()),
        sha256=pdf_sha256,
        page_count=page_count,
        title=str(info["title"]),
        author=str(info["author"]),
        created=str(info["created"]),
        pages=page_rows,
        skipped_pages=skipped,
        engine="pdftotext",
        engine_version=engine_version,
        duration_ms=duration_ms,
        truncated=any_truncation or bool(skipped),
        raw_stderr=combined_stderr,
        raw_stdout_sha256=rollup_sha256,
    )


__all__ = ["PdfDocument", "PdfPage", "parse_page_spec", "pdf_extract_text"]
