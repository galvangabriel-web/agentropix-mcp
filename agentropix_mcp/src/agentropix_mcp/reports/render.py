"""ADR-024 — render pipeline: Markdown -> HTML (pure-pip) -> PDF (gated).

Pipeline (ADR-024 §Rendering pipeline):
  1. Markdown(+Mermaid) is the source of truth (markdown.py).
  2. HTML tier: Markdown -> HTML via the pure-pip ``markdown`` library
     (no system binary, offline). Self-contained single string.
  3. PDF tier: behind a CAPABILITY CHECK.
       * default engine: headless Chromium (most robust for CSS paged-media
         + diagrams).
       * fallback engine: WeasyPrint + pre-rendered SVG (pure-Python).
     If neither toolchain is available, ``render_pdf`` raises
     ``ToolchainUnavailable`` carrying actionable install hints — it never
     performs a system/apt install (Wave-0 hard-stop, ADR-024 offline
     constraint).

Heavy deps (``markdown``, ``jinja2``, ``weasyprint``) live behind the
``[reports]`` optional-dependency group; this module imports them lazily so
the core package import stays light and a missing extra degrades gracefully.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from importlib import util as _import_util

__all__ = [
    "PdfCapability",
    "ToolchainUnavailable",
    "detect_pdf_capability",
    "render_html",
    "render_pdf",
]


# pip-only install hints (NO apt — ADR-024 hard-stop). Chromium itself is a
# system binary; we surface the hint but never auto-install it.
_CHROMIUM_HINT = (
    "headless Chromium not found on PATH. Install a chromium binary "
    "(packaging decision; e.g. the distro's `chromium` package) and ensure "
    "`chromium`/`chromium-browser`/`google-chrome` is on PATH. "
    "This engine is the ADR-024 default for fidelity."
)
_WEASYPRINT_HINT = (
    "WeasyPrint not importable. Install the reports extra: "
    "`uv add --optional reports weasyprint` (or `pip install "
    "'agentropix-sift[reports]'`). WeasyPrint is the pure-Python fallback; "
    "use the mmdc SVG-prerender path for diagrams (ADR-024 §3)."
)
_MARKDOWN_HINT = (
    "the `markdown` library is not installed. Install the reports extra: "
    "`uv add --optional reports markdown` (or `pip install "
    "'agentropix-sift[reports]'`)."
)


class ToolchainUnavailable(RuntimeError):
    """Raised when a render toolchain is absent.

    Carries ``install_hint`` (pip/packaging guidance) so the caller can
    surface an actionable message instead of a bare traceback. Never raised
    for HTML (pure-pip) — only for the PDF path when no engine is usable.
    """

    def __init__(self, message: str, *, install_hint: str = "") -> None:
        super().__init__(message)
        self.install_hint = install_hint


@dataclass(frozen=True)
class PdfCapability:
    """Outcome of the PDF capability probe (no side effects)."""

    available: bool
    engine: str = ""  # "chromium" | "weasyprint" | ""
    chromium_path: str = ""
    weasyprint_importable: bool = False
    hints: list[str] = field(default_factory=list)


def _find_chromium() -> str:
    for binary in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
        path = shutil.which(binary)
        if path:
            return path
    return ""


def _module_available(name: str) -> bool:
    try:
        return _import_util.find_spec(name) is not None
    except (ModuleNotFoundError, ValueError):
        return False


def detect_pdf_capability(*, prefer: str = "chromium") -> PdfCapability:
    """Probe for a usable PDF engine WITHOUT installing anything.

    Returns the selected engine per the ADR-024 default (chromium) with a
    WeasyPrint fallback. ``prefer="weasyprint"`` flips the preference order.
    """
    chromium = _find_chromium()
    weasy = _module_available("weasyprint")

    order = ("weasyprint", "chromium") if prefer == "weasyprint" else ("chromium", "weasyprint")
    hints: list[str] = []
    for engine in order:
        if engine == "chromium" and chromium:
            return PdfCapability(
                available=True,
                engine="chromium",
                chromium_path=chromium,
                weasyprint_importable=weasy,
            )
        if engine == "weasyprint" and weasy:
            return PdfCapability(
                available=True,
                engine="weasyprint",
                chromium_path=chromium,
                weasyprint_importable=weasy,
            )
    if not chromium:
        hints.append(_CHROMIUM_HINT)
    if not weasy:
        hints.append(_WEASYPRINT_HINT)
    return PdfCapability(
        available=False,
        engine="",
        chromium_path=chromium,
        weasyprint_importable=weasy,
        hints=hints,
    )


_HTML_SHELL = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>{css}</style>
</head>
<body>
{body}
</body>
</html>
"""

# Minimal self-contained paged-media stylesheet (ADR-024 §5): no network, and
# the highest-leverage PDF-quality rule — never split code/tables/figures.
_DEFAULT_CSS = (
    "@page { size: A4; margin: 18mm; }\n"
    "body { font-family: sans-serif; line-height: 1.4; }\n"
    "table { border-collapse: collapse; width: 100%; }\n"
    "th, td { border: 1px solid #888; padding: 4px 6px; text-align: left; }\n"
    "pre, table, figure, .mermaid { break-inside: avoid; page-break-inside: avoid; }\n"
    ".pagebreak { break-before: page; }\n"
)


def render_html(markdown_text: str, *, title: str = "SIFT Report", css: str | None = None) -> str:
    """Render Markdown -> a self-contained HTML string (pure-pip, offline).

    Raises ``ToolchainUnavailable`` with an install hint if the pure-pip
    ``markdown`` library is not installed (the reports extra).
    """
    if not _module_available("markdown"):
        raise ToolchainUnavailable(
            "the `markdown` library is required to render HTML",
            install_hint=_MARKDOWN_HINT,
        )
    import markdown as _md  # lazy: keeps core import light

    body = _md.markdown(
        markdown_text,
        extensions=["tables", "fenced_code", "toc", "attr_list"],
    )
    return _HTML_SHELL.format(title=title, css=css if css is not None else _DEFAULT_CSS, body=body)


def render_pdf(
    markdown_text: str,
    output_path: str,
    *,
    title: str = "SIFT Report",
    prefer: str = "chromium",
    capability: PdfCapability | None = None,
) -> str:
    """Render Markdown -> PDF at ``output_path`` behind a capability check.

    The HTML intermediate is produced first (pure-pip), then handed to the
    selected engine. If no engine is available, raises ``ToolchainUnavailable``
    with combined install hints and DOES NOT install anything.

    Returns ``output_path`` on success.
    """
    cap = capability if capability is not None else detect_pdf_capability(prefer=prefer)
    if not cap.available:
        raise ToolchainUnavailable(
            "no PDF render engine available (need headless Chromium or WeasyPrint)",
            install_hint=" ".join(cap.hints),
        )

    html = render_html(markdown_text, title=title)

    if cap.engine == "weasyprint":
        from weasyprint import HTML as _WeasyHTML  # lazy import

        _WeasyHTML(string=html).write_pdf(output_path)
        return output_path

    # chromium: write the HTML to a sibling temp file and print to PDF
    # headless. Implemented per ADR-024; the system binary itself is a
    # packaging decision and is NOT installed here.
    import subprocess
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False, encoding="utf-8") as fh:
        fh.write(html)
        html_path = fh.name
    cmd = [
        cap.chromium_path,
        "--headless=new",
        "--no-sandbox",
        "--disable-gpu",
        f"--print-to-pdf={output_path}",
        "--no-pdf-header-footer",
        f"file://{html_path}",
    ]
    subprocess.run(cmd, check=True, capture_output=True, timeout=120)
    return output_path
