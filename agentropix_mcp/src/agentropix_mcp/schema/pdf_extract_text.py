"""W-103 — typed result schema for the ``pdf_extract_text`` MCP tool.

Mirrors the per-entry / batch shape established by
``schema/extract_archive.py``: one row per requested PDF page so a
single bad page never fails the whole call. Document-level metadata
(page count, optional title/author/created) lives on the parent
``PdfDocument`` model alongside the chain-of-custody anchor
(``sha256`` of the source bytes + ``raw_stdout_sha256`` of the
concatenated extracted text).
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class PdfPage(BaseModel):
    """One row of the per-page extraction manifest."""

    page: int
    """1-indexed page number within the source document."""

    ok: bool = True
    """True when the page was extracted cleanly. False when ``pdftotext``
    raised a per-page error (rendering, encoding, timeout) — the batch
    continues; mirrors the ``ExtractedFile`` / ``ArchiveEntry`` shape."""

    error: str = ""
    """Populated when ``ok`` is False."""

    text: str = ""
    """Extracted plain text. May be truncated to ``max_chars`` per the
    wrapper's per-page cap (``AGENTROPIX_PDF_MAX_CHARS``)."""

    char_count: int = 0
    """Byte-count of ``text`` after any truncation."""

    truncated: bool = False
    """True when this page's text was clipped to ``max_chars``."""


class PdfDocument(BaseModel):
    """Structured result of one ``pdf_extract_text`` call."""

    target: str
    """Resolved absolute path of the source PDF."""

    sha256: str = ""
    """SHA-256 of the raw PDF bytes — chain-of-custody anchor (W-082)."""

    page_count: int = 0
    """Total pages in the source document, as reported by ``pdfinfo``."""

    title: str = ""
    """Document Title from ``pdfinfo`` metadata (empty when absent)."""

    author: str = ""
    """Document Author from ``pdfinfo`` metadata (empty when absent)."""

    created: str = ""
    """Raw ``CreationDate`` string from ``pdfinfo`` (empty when absent).
    Left as a free-form string because PDF dates may use any of the
    ``D:YYYYMMDDHHmmSS`` variants — downstream tooling can normalise."""

    pages: list[PdfPage] = Field(default_factory=list)
    """Extracted pages in source order. Restricted to the caller's
    ``pages`` selector; capped by ``max_pages``."""

    skipped_pages: list[int] = Field(default_factory=list)
    """Page numbers that were requested but trimmed by the
    ``max_pages`` cap (preserves the cap-victim list for audit)."""

    engine: str = "pdftotext"
    """Engine actually used. Currently always ``"pdftotext"``; the field
    is retained for forward-compatibility with pypdf / pdfminer
    fallbacks documented in the draft spec."""

    engine_version: str = ""
    """First line of ``pdftotext -v`` output, captured once per call."""

    duration_ms: float = 0.0
    """Wall-clock time spent in the wrapper, including all per-page
    subprocess invocations."""

    truncated: bool = False
    """True when at least one page hit ``max_chars`` OR ``skipped_pages``
    is non-empty — single boolean for downstream `truncated` filters."""

    tool: str = "pdf_extract_text"
    raw_stderr: str = ""
    """Concatenated ``pdftotext`` stderr capped at 1000 chars."""

    raw_stdout_sha256: str = ""
    """SHA-256 over ``"\\n\\f".join(p.text for p in pages)`` — gives
    downstream tooling a cheap reproducibility check that two
    re-extractions of the same PDF produced identical output."""


__all__ = ["PdfDocument", "PdfPage"]
