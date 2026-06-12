"""Courtroom-track helpers — chain-of-custody integrity for the SIFT report.

ADR-016 (BMAD-M8 Phase M8.2) defines the **High Inference Constraint**
contract: the LLM agents (Architect, Critic) only orchestrate; every fact
in the report originates from a named deterministic MCP tool. This module
adds the cryptographic invariants that make the report court-defensible:

1. ``evidence_image_sha256(path)`` — hash the evidence image at session
   start so the report is provably tied to the bytes-on-disk that were
   triaged. Streams the file in 1 MiB chunks; degrades gracefully when the
   path is missing, a directory, or too large to hash within the env-var
   budget.

2. ``seal_report(report_json, key)`` / ``verify_seal(report_json, key,
   seal)`` — HMAC-SHA256 envelope around a *canonicalised* JSON
   serialisation of the report (sort_keys=True, no indent) so a tamper of
   any byte produces a different MAC.

3. ``write_session_key(out_path)`` — generate 32 random bytes via
   ``secrets.token_bytes`` and write to ``<out>.session-key`` with mode
   0600. The verifier reads this file alongside the report.

4. ``write_sealed_report(report_dict, out_path)`` — convenience: serialise,
   seal, embed the seal under ``report_seal``, write report.json + key file.

5. ``seal_audit_log(audit_dict, key)`` / ``verify_audit_seal`` /
   ``read_audit_log_jsonl(path)`` / ``write_sealed_session`` (ADR-022,
   W-173) — independent HMAC-sealed audit-log file alongside the report.
   Closes the M8.6-era gap where the Thymus access trail (in-memory ring
   + on-disk JSONL) survived only as long as the report.json envelope:
   the audit log is now a peer-sealed file with cross-binding into the
   report seal, so post-hoc tampering of either file is detectable from
   the other.

Design notes:
  * The session key is **per-run**, not a long-lived secret. The threat
    model is post-hoc tampering of the JSON, not impersonation.
  * No JOSE / JWT machinery; HMAC-SHA256 over canonical JSON is the
    smallest primitive that achieves the goal.
  * The seal field is *included in the JSON* but with a placeholder during
    canonicalisation — see :func:`_canonical_for_seal`.
  * Hashing the evidence image is **best-effort**: skipping (None) is
    acceptable and explicitly recorded in the report. A judge values
    "we tried; here is the size threshold" over a silent failure.
  * Audit-log seal uses the **same per-run session key** as the report
    seal. Cross-binding embeds ``audit_log_seal`` in the report dict
    *before* the report seal is computed, so a verifier that only has
    the report can still detect a swapped audit-log file by recomputing
    the audit seal and comparing.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
from pathlib import Path

logger = logging.getLogger(__name__)

# Streaming chunk size for image hashing. 1 MiB balances syscall count vs.
# RAM footprint; can be tuned if profiling demands.
_HASH_CHUNK_BYTES = 1024 * 1024

# Default cap on evidence-image size to hash. Can be raised by operators
# who routinely triage 100+ GB E01 containers and accept the wall-clock
# cost. The cap is intentionally generous (50 GB) so most cases hash
# inline; truly huge containers can be hashed offline and the digest
# embedded via ``AGENTROPIX_EVIDENCE_SHA256`` (operator override).
_DEFAULT_MAX_HASH_BYTES = 50 * 1024 * 1024 * 1024


def _resolve_max_hash_bytes() -> int:
    """Return the max bytes to hash (env-var-tunable, floor 1 MiB)."""
    raw = os.environ.get("AGENTROPIX_HASH_MAX_BYTES")
    if not raw:
        return _DEFAULT_MAX_HASH_BYTES
    try:
        value = int(raw)
    except ValueError:
        logger.warning("Invalid AGENTROPIX_HASH_MAX_BYTES=%r — using default", raw)
        return _DEFAULT_MAX_HASH_BYTES
    return max(value, 1024 * 1024)


def evidence_image_sha256(path: Path) -> str | None:
    """Return SHA-256 hex digest of the evidence image at ``path``.

    Returns None when:
      * the path is missing or not a regular file (e.g. a directory that
        the orchestrator was pointed at by mistake);
      * the file exceeds ``AGENTROPIX_HASH_MAX_BYTES`` (default 50 GB);
      * the operator has supplied an offline-computed digest via
        ``AGENTROPIX_EVIDENCE_SHA256`` (in which case that value is
        returned verbatim — the orchestrator embeds it without recomputing).

    The function never raises; it always returns ``str | None`` so the
    seal pipeline degrades gracefully on un-hashable inputs.
    """
    override = os.environ.get("AGENTROPIX_EVIDENCE_SHA256", "").strip()
    if override:
        # Allow operator override for huge containers hashed offline.
        # Length-check only; value is operator-supplied so we trust it.
        if len(override) == 64 and all(c in "0123456789abcdefABCDEF" for c in override):
            return override.lower()
        logger.warning("AGENTROPIX_EVIDENCE_SHA256 must be a 64-char hex string; ignoring.")

    try:
        if not path.exists() or not path.is_file():
            return None
        size = path.stat().st_size
    except OSError as exc:
        logger.warning("Unable to stat evidence image %s: %s", path, exc)
        return None

    cap = _resolve_max_hash_bytes()
    if size > cap:
        logger.warning(
            "Evidence image %s is %d bytes, exceeds AGENTROPIX_HASH_MAX_BYTES=%d. "
            "Skipping inline hash; set AGENTROPIX_EVIDENCE_SHA256 with an "
            "offline-computed digest to embed it in the report.",
            path,
            size,
            cap,
        )
        return None

    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            while True:
                chunk = fh.read(_HASH_CHUNK_BYTES)
                if not chunk:
                    break
                h.update(chunk)
    except OSError as exc:
        logger.warning("Failed to hash evidence image %s: %s", path, exc)
        return None
    return h.hexdigest()


def _canonical_for_seal(report_dict: dict) -> bytes:
    """Canonicalise the report for HMAC.

    The seal field is *part of the document* but obviously cannot be
    included in the bytes-being-MACed — so this helper builds a copy with
    ``report_seal`` forced to a fixed sentinel before serialising. The
    verifier does the same, so the MAC is reproducible.

    JSON canonicalisation: ``sort_keys=True``, ``separators=(",", ":")``
    (no whitespace), ``ensure_ascii=True``. Same on both sides.
    """
    snapshot = dict(report_dict)
    snapshot["report_seal"] = "__sealed__"
    return json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str).encode()


def seal_report(report_dict: dict, key: bytes) -> str:
    """Compute the HMAC-SHA256 hex digest over the canonicalised report.

    The result is embedded in ``report_dict["report_seal"]``; the JSON on
    disk includes the seal so verifiers do not need a side-channel.
    """
    if len(key) < 32:
        raise ValueError("Session key must be ≥ 32 bytes")
    payload = _canonical_for_seal(report_dict)
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def verify_seal(report_dict: dict, key: bytes, expected_seal: str) -> bool:
    """Constant-time verification of a previously-sealed report.

    Returns ``True`` when the recomputed MAC matches ``expected_seal``
    byte-for-byte, ``False`` otherwise. Uses ``hmac.compare_digest`` to
    avoid timing-side-channel leaks (overkill for this threat model but
    cheap enough to do correctly).
    """
    recomputed = seal_report(report_dict, key)
    return hmac.compare_digest(recomputed, expected_seal)


def write_session_key(out_path: Path) -> tuple[bytes, Path]:
    """Generate a 32-byte session key and write it next to the report.

    Returns ``(key_bytes, key_path)``. The key file is written with mode
    0600 (user-rw only); operators are responsible for any further OS-
    level ACLs needed for evidentiary handling. ``out_path`` is the JSON
    report path; the key lives at ``<stem>.session-key`` in the same
    directory. If a key file already exists at that path, it is overwritten
    (one key per run).
    """
    key = secrets.token_bytes(32)
    key_path = out_path.parent / f"{out_path.stem}.session-key"
    key_path.write_bytes(key)
    try:
        os.chmod(key_path, 0o600)
    except OSError as exc:  # pragma: no cover  — non-POSIX FS
        logger.warning("Unable to chmod 0600 on %s: %s", key_path, exc)
    return key, key_path


def write_sealed_report(report_dict: dict, out_path: Path) -> Path:
    """Convenience: generate session key, seal the report, write both files.

    Order of operations:
      1. ``write_session_key(out_path)`` → returns ``(key, key_path)``.
      2. ``seal_report(report_dict, key)`` → seal hex digest.
      3. Embed seal under ``report_dict["report_seal"]``.
      4. Write canonicalised JSON to ``out_path`` (indent=2 for human
         readability; the seal was computed over the canonical form so
         indentation does not affect verification).

    Returns the path to the report (not the key) for caller convenience.

    For new code, prefer :func:`write_sealed_session` which additionally
    seals the Thymus audit log into a peer file and cross-binds it into
    the report seal. ``write_sealed_report`` is retained for callers that
    do not have audit entries to seal (legacy and test paths).
    """
    key, _key_path = write_session_key(out_path)
    seal = seal_report(report_dict, key)
    report_dict["report_seal"] = seal
    out_path.write_text(json.dumps(report_dict, indent=2, default=str))
    return out_path


# ---------------------------------------------------------------------------
# W-173 / ADR-022 — independent HMAC-sealed audit log
#
# Until 2026-05-06 the Thymus access trail (ALLOW/REJECT/REJECT_WRITE) was
# kept in two places: an in-memory bounded ring (see
# ``mcp_server.thymus_policy.ThymusEvidencePolicy._audit_log``) and an
# append-only on-disk JSONL when ``AGENTROPIX_AUDIT_LOG`` was set. Neither
# was sealed, so a hostile reviewer who replaced ``report.json`` could
# also rewrite the JSONL silently — defeating the chain-of-custody story
# the report seal was meant to provide.
#
# The audit-log seal (W-173) closes that gap with three mechanisms:
#
# 1. The audit-log file (``<stem>.audit-log.json``) carries its own
#    HMAC-SHA256 over a canonicalised dump of its entries, computed with
#    the same per-run session key as the report seal.
# 2. The same audit seal is embedded in the report dict under
#    ``audit_log_seal`` *before* the report seal is computed. Tampering
#    with the audit log breaks the audit seal and the report seal (which
#    was MACed over the audit_log_seal field).
# 3. ``read_audit_log_jsonl`` drains the on-disk JSONL at session end so
#    the sealed file is a snapshot of the trail-of-record rather than the
#    bounded in-memory ring (which can have rolled past its capacity
#    during long runs).
# ---------------------------------------------------------------------------


def _canonical_for_audit_seal(audit_dict: dict) -> bytes:
    """Canonicalise an audit-log dict for HMAC.

    Mirrors :func:`_canonical_for_seal`: replaces the seal field with a
    fixed sentinel, then dumps JSON with ``sort_keys=True`` and minimal
    separators so the verifier produces byte-identical input.
    """
    snapshot = dict(audit_dict)
    snapshot["audit_log_seal"] = "__sealed__"
    return json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str).encode()


def seal_audit_log(audit_dict: dict, key: bytes) -> str:
    """HMAC-SHA256 over the canonicalised audit-log dict.

    The expected dict shape is ``{"audit_entries": [...], "metadata":
    {...}, "audit_log_seal": <will-be-sentinelised>}``. The seal field
    may be present or absent; canonicalisation replaces it with a fixed
    sentinel so the seal can be embedded after computation without
    re-MACing.
    """
    if len(key) < 32:
        raise ValueError("Session key must be >= 32 bytes")
    payload = _canonical_for_audit_seal(audit_dict)
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def verify_audit_seal(audit_dict: dict, key: bytes, expected_seal: str) -> bool:
    """Constant-time verification of a previously-sealed audit log."""
    recomputed = seal_audit_log(audit_dict, key)
    return hmac.compare_digest(recomputed, expected_seal)


def read_audit_log_jsonl(path: Path | None) -> list[dict]:
    """Drain a Thymus audit-log JSONL file into a list of entries.

    Tolerant of missing path, missing file, and malformed lines:
      * ``path`` is None or the file does not exist → returns ``[]``.
      * Unparseable lines are skipped with a warning; valid lines are
        kept in their on-disk order. (The on-disk JSONL is append-only
        from a single writer, so on-disk order == chronological order.)

    The returned list is what the orchestrator passes to
    :func:`write_sealed_session` as ``audit_entries``.
    """
    if path is None:
        return []
    try:
        if not path.exists() or not path.is_file():
            return []
    except OSError as exc:
        logger.warning("Unable to stat audit log %s: %s", path, exc)
        return []
    entries: list[dict] = []
    try:
        with path.open("r") as fh:
            for lineno, raw in enumerate(fh, start=1):
                line = raw.strip()
                if not line:
                    continue
                try:
                    parsed = json.loads(line)
                except json.JSONDecodeError as exc:
                    logger.warning(
                        "Skipping malformed audit-log line %d in %s: %s",
                        lineno,
                        path,
                        exc,
                    )
                    continue
                if isinstance(parsed, dict):
                    entries.append(parsed)
                else:
                    logger.warning(
                        "Skipping non-object audit-log line %d in %s",
                        lineno,
                        path,
                    )
    except OSError as exc:
        logger.warning("Failed to read audit log %s: %s", path, exc)
        return entries
    return entries


def write_sealed_session(
    report_dict: dict,
    audit_entries: list[dict],
    out_path: Path,
    *,
    audit_log_source_path: Path | None = None,
) -> dict[str, Path]:
    """Write report.json + audit-log.json + session-key, sealed and cross-bound.

    Single-key flow so both seals are produced under the same per-run
    HMAC key:

      1. Generate the session key once via :func:`write_session_key`.
      2. Build the audit-log dict with metadata + entries; compute its
         seal; embed it under ``audit_log_seal``.
      3. Cross-bind: copy ``audit_log_seal`` into the report dict so the
         report seal MACs over it. A swapped audit-log file with a valid
         internal seal but a different MAC will still fail the cross
         check.
      4. Compute and embed ``report_seal``; write report.json.
      5. Write ``<stem>.audit-log.json``.

    Returns a dict ``{"report": Path, "key": Path, "audit": Path}`` so
    callers can echo all three surfaces to the operator.

    ``audit_log_source_path`` is optional metadata only — it records
    where the entries were drained from (the value of
    ``AGENTROPIX_AUDIT_LOG`` at session start) so a verifier can see
    whether on-disk JSONL audit logging was enabled. ``None`` is fine
    and means "in-memory ring only or audit log disabled".
    """
    key, key_path = write_session_key(out_path)

    audit_dict: dict = {
        "metadata": {
            "audit_log_enabled": audit_log_source_path is not None,
            "entry_count": len(audit_entries),
            "audit_log_source_path": (str(audit_log_source_path) if audit_log_source_path else None),
        },
        "audit_entries": list(audit_entries),
    }
    audit_seal = seal_audit_log(audit_dict, key)
    audit_dict["audit_log_seal"] = audit_seal

    # Cross-bind: report seal MACs over the audit_log_seal field, so a
    # post-hoc swap of the audit-log file fails the report seal too.
    report_dict["audit_log_seal"] = audit_seal

    report_seal = seal_report(report_dict, key)
    report_dict["report_seal"] = report_seal

    out_path.write_text(json.dumps(report_dict, indent=2, default=str))

    audit_path = out_path.parent / f"{out_path.stem}.audit-log.json"
    audit_path.write_text(json.dumps(audit_dict, indent=2, default=str))

    return {"report": out_path, "key": key_path, "audit": audit_path}
