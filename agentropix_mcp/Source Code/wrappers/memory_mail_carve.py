"""memory->EML carve sidecar -- extracts email artifacts from memory dumps
so MailAgent can run T1566 detection on memory-only hosts.

For large images (e.g. 17 GB base-mail-memory.img), operators may want to
run this in a background process since bulk_extractor scanning can be slow.
The AGENTROPIX_MEM_MAIL_CARVE_BUDGET_MB env var (default 4096 MB) gates
execution: images over budget return [] immediately without scanning.
"""

from __future__ import annotations

import hashlib
import logging
import subprocess
from email.parser import BytesParser
from pathlib import Path

from agentropix_mcp._env import get_int

logger = logging.getLogger(__name__)

_DEFAULT_BUDGET_MB = 4096
_DEFAULT_MIN_HEADER_COUNT = 2

_CHUNK_SIZE = 4 * 1024 * 1024  # 4 MB
_WINDOW_OVERLAP = 4096          # bytes shared between consecutive chunks


def _read_budget_mb() -> int:
    return get_int(
        "AGENTROPIX_MEM_MAIL_CARVE_BUDGET_MB",
        _DEFAULT_BUDGET_MB,
        floor=64,
        ceiling=32768,
    )


def _read_min_header_count() -> int:
    return get_int(
        "AGENTROPIX_MEM_MAIL_MIN_HEADER_COUNT",
        _DEFAULT_MIN_HEADER_COUNT,
        floor=1,
        ceiling=10,
    )


def _count_headers(msg) -> int:
    """Return number of non-empty headers in a parsed email.Message."""
    return sum(1 for k, v in msg.items() if k and v)


_MAX_CANDIDATES_PER_WINDOW = 512


def _extract_candidates_from_window(window: bytes) -> list[bytes]:
    """Find RFC 822 candidate blocks starting with 'From:' in a window.

    Looks for b'\\nFrom: ' and b'\\r\\nFrom: ' markers as block starts.
    Each candidate runs from the marker to the next occurrence or end.
    Capped at _MAX_CANDIDATES_PER_WINDOW to bound per-chunk memory.
    """
    # marker -> how many bytes of line-ending prefix to skip so block
    # starts at the 'F' of 'From:'.
    search_markers: list[tuple[bytes, int]] = [
        (b"\nFrom: ", 1),    # skip the leading \n
        (b"\r\nFrom: ", 2),  # skip the leading \r\n
    ]

    # Collect all positions where a From: header starts (at 'F')
    positions: list[int] = []
    for marker, prefix_skip in search_markers:
        start = 0
        while True:
            pos = window.find(marker, start)
            if pos == -1:
                break
            block_start = pos + prefix_skip
            positions.append(block_start)
            start = pos + 1

    positions = sorted(set(positions))

    candidates: list[bytes] = []
    for i, pos in enumerate(positions):
        if len(candidates) >= _MAX_CANDIDATES_PER_WINDOW:
            break
        end = positions[i + 1] if i + 1 < len(positions) else len(window)
        candidates.append(window[pos:end])

    return candidates


def carve_emails_from_memory(
    image_path: Path,
    out_dir: Path | None = None,
) -> list[Path]:
    """Carve RFC 822 email artifacts from a memory dump image.

    Runs bulk_extractor -E email on the image, then performs a
    sliding-window scan of the raw image bytes to reconstruct EML files
    from RFC 822 header sequences. Deduplicates by SHA-256 and writes
    each unique EML to out_dir.

    Args:
        image_path: Path to the memory dump image file.
        out_dir: Directory to write carved EML files. Defaults to
            image_path.parent / "_carved" / image_path.stem.

    Returns:
        List of paths to written .eml files. Returns [] on budget
        exceeded, missing bulk_extractor, or bulk_extractor failure.

    Note:
        For large images (e.g. 17 GB), bulk_extractor scanning is slow.
        Consider running in a background process for production use.
    """
    if out_dir is None:
        out_dir = image_path.parent / "_carved" / image_path.stem

    out_dir.mkdir(parents=True, exist_ok=True)

    # Budget check
    budget_mb = _read_budget_mb()
    budget_bytes = budget_mb * 1024 * 1024
    try:
        image_size = image_path.stat().st_size
    except OSError as exc:
        logger.warning("memory_mail_carve: cannot stat %s: %s", image_path, exc)
        return []

    if image_size > budget_bytes:
        logger.warning(
            "memory_mail_carve: %s is %d MB, exceeds budget %d MB; skipping",
            image_path,
            image_size // (1024 * 1024),
            budget_mb,
        )
        return []

    # Run bulk_extractor
    scanner_outdir = out_dir / "be_output"
    scanner_outdir.mkdir(parents=True, exist_ok=True)

    try:
        result = subprocess.run(
            [
                "bulk_extractor",
                "-E", "email",
                "-o", str(scanner_outdir),
                str(image_path),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=3600,
        )
    except FileNotFoundError:
        logger.warning(
            "memory_mail_carve: bulk_extractor not found; skipping bulk_extractor phase"
        )
        result = None
    except subprocess.TimeoutExpired:
        logger.warning("memory_mail_carve: bulk_extractor timed out on %s", image_path)
        result = None

    if result is not None and result.returncode != 0:
        logger.warning(
            "memory_mail_carve: bulk_extractor exited %d for %s; stderr: %s",
            result.returncode,
            image_path,
            result.stderr[:2000] if result.stderr else b"",
        )
        # Non-zero exit: log but still attempt the sliding-window scan
        # (bulk_extractor may emit partial results or fail on this image
        # format while raw RFC 822 headers remain recoverable)

    # Sliding-window RFC 822 scan
    min_headers = _read_min_header_count()
    seen_hashes: set[str] = set()
    written_paths: list[Path] = []

    parser = BytesParser()
    window = b""

    try:
        with image_path.open("rb") as fh:
            while True:
                chunk = fh.read(_CHUNK_SIZE)
                if not chunk:
                    break
                window = window[-_WINDOW_OVERLAP:] + chunk

                candidates = _extract_candidates_from_window(window)
                for block in candidates:
                    try:
                        msg = parser.parsebytes(block)
                    except Exception:
                        continue

                    from_hdr = msg.get("From", "").strip()
                    subject_hdr = msg.get("Subject", "").strip()

                    if not from_hdr or not subject_hdr:
                        continue

                    if _count_headers(msg) < min_headers:
                        continue

                    # Deduplicate by parsed headers when Message-ID is present
                    # (same email at different offsets produces different trailing
                    # context but identical headers).  When Message-ID is absent —
                    # common in carved fragments — fall back to raw-block SHA so
                    # distinct emails with identical From+Subject are not collapsed.
                    from_val = msg.get("From", "").strip()
                    subject_val = msg.get("Subject", "").strip()
                    msgid_val = msg.get("Message-ID", "").strip()
                    if msgid_val:
                        dedup_key = f"{from_val}\x00{subject_val}\x00{msgid_val}"
                        sha = hashlib.sha256(dedup_key.encode("utf-8", errors="replace")).hexdigest()
                    else:
                        sha = hashlib.sha256(block).hexdigest()
                    if sha in seen_hashes:
                        continue
                    seen_hashes.add(sha)

                    eml_bytes = block
                    out_path = out_dir / f"{sha[:16]}.eml"
                    try:
                        out_path.write_bytes(eml_bytes)
                        written_paths.append(out_path)
                    except OSError as exc:
                        logger.warning(
                            "memory_mail_carve: cannot write %s: %s", out_path, exc
                        )
    except OSError as exc:
        logger.warning("memory_mail_carve: error reading %s: %s", image_path, exc)
        return written_paths

    return written_paths
