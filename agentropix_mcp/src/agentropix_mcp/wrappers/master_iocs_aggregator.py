"""MASTER-IOCS aggregator (W-203).

Walks ``<run-dir>/memory/<host>/report.json`` and
``<run-dir>/disks/<host>/report.json``, extracts the
``_source=memory.process_tree`` Finding entries, parses their evidence
strings, dedupes per ``(host, image_key, parent_pid)``, and writes the
result into ``<run-dir>/MASTER-IOCS.json`` as additive
``kind="process_tree_event"`` rows alongside any legacy ``iocs[]``
already on disk.

Design source: ``DESIGNS/W-203-design.md`` (§§1-10). Phase 0.5 schema
shape resolution: Branch A-prime --
``DESIGNS/W-203-schema-shape.md``.

Output envelope
---------------

The output object is canonicalised with
``json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True,
default=str)`` so re-runs are byte-identical (G3 idempotency) and the
HMAC signer can name canonicalisation as
``rfc8785-py-substitute``.

A sidecar at ``<run-dir>/MASTER-IOCS.json.signature`` binds the writer's
identifier, the SHA-256 of the canonical bytes, and the HMAC-SHA256 over
those bytes. Verification is fail-closed -- see §2.2 of the design and
the verify helper at the bottom of this module.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from itertools import chain
from pathlib import Path
from typing import Any

from agentropix_mcp.security.redact import (
    REDACTOR_KEY_ENV,
    RedactionError,
    redact_finding,
)

__all__ = [
    "AggregatorConfig",
    "AggregatorError",
    "MasterIOCSIntegrityError",
    "aggregate",
    "load_master_iocs",
    "verify_master_iocs_signature",
    "SCHEMA_VERSION",
    "SIGNER_KEY_ENV",
    "MAX_SKIP_RATIO_ENV",
]

logger = logging.getLogger(__name__)


SCHEMA_VERSION = "2026-05-14.v2"
SIGNER_KEY_ENV = "AGENTROPIX_MASTER_IOCS_HMAC_KEY"
MAX_SKIP_RATIO_ENV = "AGENTROPIX_MASTER_IOCS_MAX_SKIP_RATIO"
_SIGNER_KEY_MIN_BYTES = 32
_OUTPUT_SIZE_CEILING_BYTES = 2_000_000  # round-4 c2-F7: absolute 2 MB ceiling
_HEALTH_FILENAME = ".health"
_MITRE_ORPHAN = "T1564.012"
_MITRE_SUSPICIOUS = "T1218"
_GENERATOR_MODULE = "agentropix_mcp.wrappers.master_iocs_aggregator"


class AggregatorError(Exception):
    """Raised on fatal aggregator failures (schema, skip-overflow, mount loss, sign)."""


class MasterIOCSIntegrityError(Exception):
    """Raised when the MASTER-IOCS sidecar fails verification (fail-closed)."""


# ---------------------------------------------------------------------------
# Config + CLI exit codes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AggregatorConfig:
    """Inputs for one aggregator invocation."""

    run_dir: Path
    output_path: Path
    case_id: str
    max_skipped_hosts_pct: float = 0.10
    redactor_key_env: str = REDACTOR_KEY_ENV
    signer_key_env: str = SIGNER_KEY_ENV
    require_health_sentinel: bool = True
    sign: bool = True


# CLI exit codes (per design §1.3)
EXIT_OK = 0
EXIT_SCHEMA_FAIL = 1
EXIT_SKIP_OVERFLOW = 2
EXIT_MOUNT_LOSS = 3
EXIT_SIGN_FAIL = 4


# ---------------------------------------------------------------------------
# Evidence parser
# ---------------------------------------------------------------------------

# Source emitter (verified at agents/memory.py:190-230 per schema-shape Q2):
#   Orphan: "pid={pid} ppid={ppid} name={name} threads={threads} wow64={wow64}"
#   Suspicious: "pid={pid} ppid={ppid} name={name} reason={reason}"
_PT_RE = re.compile(
    r"^pid=(?P<pid>\d+)\s+ppid=(?P<ppid>\d+)\s+name=(?P<name>\S+)"
    r"(?:\s+threads=(?P<threads>\d+))?"
    r"(?:\s+wow64=(?P<wow64>True|False))?"
    r"(?:\s+reason=(?P<reason>.+))?$"
)


def parse_pt_evidence(evidence: str, description: str = "") -> dict[str, Any] | None:
    """Parse a memory.process_tree Finding evidence string.

    Returns a dict with structured fields, or ``None`` if the input did
    not match the canonical shape.
    """
    if not isinstance(evidence, str):
        return None
    m = _PT_RE.match(evidence.strip())
    if not m:
        return None
    groups = m.groupdict()
    evidence_kind = "orphan" if "Orphan process" in (description or "") else "suspicious"
    return {
        "pid": int(groups["pid"]),
        "parent_pid": int(groups["ppid"]),
        "name": groups["name"],
        "image_path_normalized": None,
        "image_sha256": None,
        "image_hash_source": "absent",
        "threads": int(groups["threads"]) if groups["threads"] else 0,
        "wow64": (groups["wow64"] == "True") if groups["wow64"] else False,
        "evidence_kind": evidence_kind,
        "evidence_reason": groups["reason"] if groups.get("reason") else None,
    }


# ---------------------------------------------------------------------------
# Helpers: env-clamping, generator id, corpus_root_id, health, atomic write
# ---------------------------------------------------------------------------


def _env_clamped_skip_ratio(default: float) -> float:
    """Read ``AGENTROPIX_MASTER_IOCS_MAX_SKIP_RATIO`` and clamp to [0, 1].

    Non-numeric values fall back to ``default``. Round-4 c4-F2 mitigation.
    """
    raw = os.environ.get(MAX_SKIP_RATIO_ENV)
    if raw is None or raw == "":
        return max(0.0, min(1.0, default))
    try:
        v = float(raw)
    except ValueError:
        logger.warning("%s not numeric (%r); using default %.3f", MAX_SKIP_RATIO_ENV, raw, default)
        return max(0.0, min(1.0, default))
    return max(0.0, min(1.0, v))


def _git_sha_short() -> str:
    """Return short git SHA of the running tree, or 'unknown'."""
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=Path(__file__).resolve().parent,
            capture_output=True,
            text=True,
            check=False,
            timeout=2,
        )
        if out.returncode == 0:
            return out.stdout.strip() or "unknown"
    except (OSError, subprocess.TimeoutExpired):
        pass
    return "unknown"


def _generator_id() -> str:
    return f"{_GENERATOR_MODULE}@{_git_sha_short()}"


def _utc_now_iso() -> str:
    return datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hmac_truncate(key: bytes, value: str, *, hex_len: int = 16) -> str:
    digest = hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"hmac-sha256:{digest[:hex_len]}"


def _load_signer_key(env_var: str) -> bytes:
    raw = os.environ.get(env_var)
    if raw is None:
        raise AggregatorError(f"{env_var} unset; cannot sign MASTER-IOCS.json (fail-closed)")
    key = raw.encode("utf-8") if isinstance(raw, str) else raw
    if len(key) < _SIGNER_KEY_MIN_BYTES:
        raise AggregatorError(
            f"{env_var} too short ({len(key)} bytes); floor is {_SIGNER_KEY_MIN_BYTES} bytes"
        )
    return key


def _load_redactor_key(env_var: str) -> bytes:
    """The redactor module sources its own key; we only need a copy for
    corpus_root_id hashing. Reuse the redactor's env var to keep the key
    domain unified for that use only."""
    raw = os.environ.get(env_var)
    if raw is None:
        raise AggregatorError(f"{env_var} unset; cannot compute corpus_root_id (fail-closed)")
    key = raw.encode("utf-8") if isinstance(raw, str) else raw
    if len(key) < _SIGNER_KEY_MIN_BYTES:
        raise AggregatorError(
            f"{env_var} too short ({len(key)} bytes); floor is {_SIGNER_KEY_MIN_BYTES} bytes"
        )
    return key


def _assert_corpus_health(run_dir: Path, require: bool) -> None:
    """R15 + round-4 c4-F1: if the operator-side health sentinel exists,
    treat its absence as fatal mount loss. If ``require`` is False, an
    absent sentinel is tolerated (tests against synthetic run dirs)."""
    sentinel = run_dir / _HEALTH_FILENAME
    if sentinel.exists():
        if sentinel.read_bytes() == b"":
            raise AggregatorError(f"corpus health sentinel empty: {sentinel}")
        return
    if require:
        raise AggregatorError(
            f"corpus health sentinel missing: {sentinel} (run invalidated; mount may have been lost)"
        )


def _canonical_bytes(obj: dict) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    ).encode("ascii")


def _write_atomic(path: Path, payload: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(payload)
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# Per-host extraction
# ---------------------------------------------------------------------------


def _per_host_findings(report_path: Path) -> list[dict[str, Any]]:
    """Stream-load one per-host report.json and return its findings array.

    Round-4 c2-F2 mitigation: the predicted whole-corpus payload is ~400 KB
    which is far below the 200 MB pre-check threshold. We load one host at
    a time (generator-fallback path per design Q9.1) so peak RSS stays
    bounded at one host's findings list at a time even if ijson is absent.
    """
    with report_path.open("rb") as fh:
        data = json.load(fh)
    findings = data.get("findings", [])
    if not isinstance(findings, list):
        return []
    return findings


def _build_event(
    *,
    host: str,
    relative_path: str,
    finding_index: int,
    finding: dict[str, Any],
    parsed: dict[str, Any],
    case_id: str,
) -> dict[str, Any]:
    """Build one ``kind=process_tree_event`` row, pass through redactor."""
    confidence_raw = finding.get("confidence", 0.75)
    try:
        confidence = float(confidence_raw)
    except (TypeError, ValueError):
        confidence = 0.75
    confidence = max(0.0, min(1.0, confidence))
    mitre = finding.get("mitre_attack")
    if mitre is None:
        mitre = _MITRE_SUSPICIOUS if parsed["evidence_kind"] == "suspicious" else _MITRE_ORPHAN
    raw = {
        "kind": "process_tree_event",
        "case_id": case_id,
        "host": host,
        "pid": parsed["pid"],
        "parent_pid": parsed["parent_pid"],
        "name": parsed["name"],
        "image_path_normalized": parsed["image_path_normalized"],
        "image_sha256": parsed["image_sha256"],
        "image_hash_source": parsed["image_hash_source"],
        "command_line_redacted": None,
        "command_line_sha256": None,
        "first_seen_utc": finding.get("timestamp"),
        "source_artifact": relative_path,
        "source_finding_index": finding_index,
        "evidence_kind": parsed["evidence_kind"],
        "evidence_reason": parsed["evidence_reason"],
        "confidence": confidence,
        "mitre": mitre,
        "threads": parsed["threads"],
        "wow64": parsed["wow64"],
    }
    return redact_finding(raw)


def _build_skipped_entry(
    *, host: str, relative_path: str, reason_class: str, reason_detail: str
) -> dict[str, Any]:
    detail = reason_detail[:200] if isinstance(reason_detail, str) else ""
    raw = {
        "host": host,
        "source_artifact": relative_path,
        "reason_class": reason_class,
        "reason_detail": detail,
    }
    redacted = redact_finding(raw)
    # Strip the redactor housekeeping flags -- the skipped row schema is
    # explicit (host, source_artifact, reason_class, reason_detail) and
    # the redactor only matters for the detail string content.
    redacted.pop("redacted", None)
    redacted.pop("redactor_version", None)
    return redacted


# ---------------------------------------------------------------------------
# Phase F: load + merge existing iocs[]
# ---------------------------------------------------------------------------


def _load_existing_iocs(output_path: Path) -> list[dict[str, Any]]:
    if not output_path.exists():
        return []
    try:
        data = json.loads(output_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        logger.warning("Existing MASTER-IOCS.json unparseable, treating as empty: %s", exc)
        return []
    iocs = data.get("iocs", [])
    if not isinstance(iocs, list):
        return []
    return [r for r in iocs if isinstance(r, dict)]


# ---------------------------------------------------------------------------
# Aggregate (Phases A..I)
# ---------------------------------------------------------------------------


@dataclass
class _AggregateOutcome:
    """Internal struct -- public callers should use ``aggregate()``."""

    events: list[dict[str, Any]] = field(default_factory=list)
    skipped: list[dict[str, Any]] = field(default_factory=list)
    total_hosts: int = 0


def aggregate(config: AggregatorConfig) -> Path:
    """Build MASTER-IOCS.json + sidecar signature; return the output path.

    Raises ``AggregatorError`` on schema-fail, skip-overflow, mount loss,
    or HMAC sign failure.
    """
    # Phase A -- pre-flight
    _assert_corpus_health(config.run_dir, require=config.require_health_sentinel)
    redactor_key = _load_redactor_key(config.redactor_key_env)

    # Phase B -- enumerate per-host JSONs
    host_jsons = sorted(
        chain(
            config.run_dir.glob("memory/*/report.json"),
            config.run_dir.glob("disks/*/report.json"),
        )
    )
    total_hosts = len(host_jsons)
    if total_hosts == 0:
        raise AggregatorError(f"no per-host report.json found under {config.run_dir}")

    # Phase C -- stream-parse, extract, dedupe
    seen_keys: set[tuple[str, str, int]] = set()
    pt_events: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    max_skip_pct = _env_clamped_skip_ratio(config.max_skipped_hosts_pct)

    for rj in host_jsons:
        host = rj.parent.name
        try:
            relative_path = str(rj.relative_to(config.run_dir))
        except ValueError:
            relative_path = rj.name
        try:
            findings = _per_host_findings(rj)
        except json.JSONDecodeError as exc:
            skipped.append(
                _build_skipped_entry(
                    host=host,
                    relative_path=relative_path,
                    reason_class="json.JSONDecodeError",
                    reason_detail=str(exc),
                )
            )
            continue
        except OSError as exc:
            raise AggregatorError(
                f"OSError reading {rj}: {exc} (likely mount loss)"
            ) from exc

        host_emitted_any = False
        for idx, finding in enumerate(findings):
            if not isinstance(finding, dict):
                continue
            src = finding.get("_source", "")
            if not isinstance(src, str) or not src.startswith("memory.process_tree"):
                continue
            parsed = parse_pt_evidence(
                finding.get("evidence", ""),
                description=finding.get("description", ""),
            )
            if parsed is None:
                skipped.append(
                    _build_skipped_entry(
                        host=host,
                        relative_path=relative_path,
                        reason_class="ParseError",
                        reason_detail=f"evidence regex did not match (finding index {idx})",
                    )
                )
                continue
            image_key = (
                parsed.get("image_sha256")
                or parsed.get("image_path_normalized")
                or parsed["name"]
            )
            dedupe_key = (host, image_key, parsed["parent_pid"])
            if dedupe_key in seen_keys:
                continue
            seen_keys.add(dedupe_key)
            try:
                event = _build_event(
                    host=host,
                    relative_path=relative_path,
                    finding_index=idx,
                    finding=finding,
                    parsed=parsed,
                    case_id=config.case_id,
                )
            except RedactionError as exc:
                raise AggregatorError(
                    f"redactor failed building event for {host} finding {idx}: {exc}"
                ) from exc
            pt_events.append(event)
            host_emitted_any = True
        if not host_emitted_any and not findings:
            # No findings at all on this host -- explicit absence ack per
            # schema-shape Q4 ("input absence ack" so W-204 can tell
            # zero-FP from zero-input).
            skipped.append(
                _build_skipped_entry(
                    host=host,
                    relative_path=relative_path,
                    reason_class="no-input",
                    reason_detail="no findings array on this host report.json",
                )
            )

    # Phase D -- skip-overflow guard
    skip_ratio = (len(skipped) / total_hosts) if total_hosts else 0.0
    if skip_ratio > max_skip_pct:
        raise AggregatorError(
            f"skipped {skip_ratio:.2%} of hosts (> {max_skip_pct:.2%}); "
            "refusing to emit silent-zero MASTER-IOCS.json"
        )

    # Phase E -- deterministic sort
    pt_events.sort(key=lambda e: (e["host"], e["pid"], e["parent_pid"]))
    skipped.sort(key=lambda e: (e["host"], e["source_artifact"]))

    # Phase F -- merge with existing iocs[] (additive, idempotent)
    existing_iocs = _load_existing_iocs(config.output_path)
    existing_iocs = [r for r in existing_iocs if r.get("kind") != "process_tree_event"]
    merged_iocs: list[dict[str, Any]] = existing_iocs + pt_events
    merged_iocs.sort(
        key=lambda r: (
            str(r.get("kind", "")),
            str(r.get("value", "") or ""),
            str(r.get("host", "") or ""),
            int(r.get("pid", -1)) if isinstance(r.get("pid"), int) else -1,
            int(r.get("parent_pid", -1)) if isinstance(r.get("parent_pid"), int) else -1,
        )
    )

    # Phase G -- build doc
    doc: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "case_id": config.case_id,
        "generated_at_utc": _utc_now_iso(),
        "generator_id": _generator_id(),
        "corpus_root_id": _hmac_truncate(redactor_key, str(config.run_dir)),
        "iocs": merged_iocs,
        "process_tree_findings_skipped": skipped,
    }

    canonical = _canonical_bytes(doc)
    if len(canonical) > _OUTPUT_SIZE_CEILING_BYTES:
        raise AggregatorError(
            f"MASTER-IOCS.json canonical size {len(canonical)} > "
            f"ceiling {_OUTPUT_SIZE_CEILING_BYTES} (round-4 c2-F7)"
        )

    # Phase H -- atomic write + sign
    config.output_path.parent.mkdir(parents=True, exist_ok=True)
    _write_atomic(config.output_path, canonical)

    if config.sign:
        try:
            signer_key = _load_signer_key(config.signer_key_env)
        except AggregatorError:
            # Roll back the partial write so we never leave an unsigned
            # MASTER-IOCS.json on disk.
            try:
                config.output_path.unlink()
            except OSError:
                pass
            raise
        target_sha256 = hashlib.sha256(canonical).hexdigest()
        signature_hex = hmac.new(signer_key, canonical, hashlib.sha256).hexdigest()
        key_id_hash = hashlib.sha256(signer_key).hexdigest()[:16]
        sidecar = {
            "version": "1",
            "algorithm": "hmac-sha256",
            "byte_coverage": "WHOLE",
            "canonicalization": "rfc8785-py-substitute",
            "key_id_hash": key_id_hash,
            "signature_hex": signature_hex,
            "signed_at_utc": _utc_now_iso(),
            "signer_id": _generator_id(),
            "target_filename": config.output_path.name,
            "target_sha256": target_sha256,
            "target_size_bytes": len(canonical),
        }
        sidecar_path = config.output_path.with_suffix(config.output_path.suffix + ".signature")
        _write_atomic(sidecar_path, _canonical_bytes(sidecar))

    # Phase I -- post-write corpus health re-check
    _assert_corpus_health(config.run_dir, require=config.require_health_sentinel)

    return config.output_path


# ---------------------------------------------------------------------------
# Verification helpers (consumed by wazuh/orchestrator -> push_iocs)
# ---------------------------------------------------------------------------


def load_master_iocs(master_iocs_path: Path) -> dict[str, Any]:
    """Read + return the parsed MASTER-IOCS.json (no signature check)."""
    return json.loads(master_iocs_path.read_text(encoding="utf-8"))


def verify_master_iocs_signature(master_iocs_path: Path, *, signer_key_env: str = SIGNER_KEY_ENV) -> None:
    """Fail-closed sidecar verification.

    Raises ``MasterIOCSIntegrityError`` on missing sidecar, mismatched
    target_sha256, mismatched target_filename, or HMAC mismatch.
    """
    sidecar_path = master_iocs_path.with_suffix(master_iocs_path.suffix + ".signature")
    if not sidecar_path.exists():
        raise MasterIOCSIntegrityError(f"sidecar missing: {sidecar_path}")
    try:
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise MasterIOCSIntegrityError(f"sidecar unparseable: {exc}") from exc
    if sidecar.get("target_filename") != master_iocs_path.name:
        raise MasterIOCSIntegrityError(
            f"sidecar target_filename mismatch: {sidecar.get('target_filename')!r} != {master_iocs_path.name!r}"
        )
    canonical = master_iocs_path.read_bytes()
    if hashlib.sha256(canonical).hexdigest() != sidecar.get("target_sha256"):
        raise MasterIOCSIntegrityError("sidecar target_sha256 mismatch (file modified?)")
    raw = os.environ.get(signer_key_env)
    if raw is None:
        raise MasterIOCSIntegrityError(f"{signer_key_env} unset; cannot verify")
    key = raw.encode("utf-8") if isinstance(raw, str) else raw
    recomputed = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    declared = sidecar.get("signature_hex", "")
    if not hmac.compare_digest(recomputed, declared):
        raise MasterIOCSIntegrityError("sidecar HMAC mismatch")


# ---------------------------------------------------------------------------
# Module entry-point shim (used by __main__.py)
# ---------------------------------------------------------------------------


def _derive_case_id(run_dir: Path, override: str | None) -> str:
    if override:
        return override
    candidate = run_dir.name.upper()
    cleaned = re.sub(r"[^A-Z0-9_\-]", "", candidate)[:64]
    if not cleaned or not cleaned[0].isalnum():
        return "UNKNOWN"
    return cleaned


def run_cli(argv: list[str] | None = None) -> int:
    """CLI entry. Exits 0 on success or a non-zero exit code per design §1.3."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="agentropix_mcp.wrappers",
        description="Aggregate per-host process_tree findings into MASTER-IOCS.json",
    )
    parser.add_argument("--input", required=True, help="run directory containing memory/ and disks/")
    parser.add_argument(
        "--output",
        default=None,
        help="output run directory (defaults to --input); MASTER-IOCS.json is written under it",
    )
    parser.add_argument("--case-id", default=None, help="override case_id (defaults to <output-dir>.name.upper())")
    parser.add_argument(
        "--max-skip-pct",
        type=float,
        default=0.10,
        help="default max skipped-hosts ratio (env AGENTROPIX_MASTER_IOCS_MAX_SKIP_RATIO overrides)",
    )
    parser.add_argument("--no-sign", action="store_true", help="skip HMAC sidecar emission (testing only)")
    parser.add_argument(
        "--no-require-health",
        action="store_true",
        help="do not require the .health sentinel under --input (testing only)",
    )
    args = parser.parse_args(argv)

    run_dir = Path(args.input).resolve()
    output_dir = Path(args.output).resolve() if args.output else run_dir
    output_path = output_dir / "MASTER-IOCS.json"
    case_id = _derive_case_id(output_dir, args.case_id)
    config = AggregatorConfig(
        run_dir=run_dir,
        output_path=output_path,
        case_id=case_id,
        max_skipped_hosts_pct=args.max_skip_pct,
        sign=not args.no_sign,
        require_health_sentinel=not args.no_require_health,
    )
    try:
        aggregate(config)
    except AggregatorError as exc:
        msg = str(exc)
        logger.error("aggregator failed: %s", msg)
        sys.stderr.write(f"aggregator-error: {msg}\n")
        if "MASTER-IOCS.json canonical size" in msg or "output failed schema" in msg:
            return EXIT_SCHEMA_FAIL
        if "skipped" in msg and "of hosts" in msg:
            return EXIT_SKIP_OVERFLOW
        if "mount loss" in msg or "corpus health sentinel" in msg or "no per-host report.json" in msg:
            return EXIT_MOUNT_LOSS
        if "cannot sign" in msg or "floor is" in msg:
            return EXIT_SIGN_FAIL
        return EXIT_SCHEMA_FAIL
    except RedactionError as exc:
        sys.stderr.write(f"RedactionError: {exc}\n")
        return EXIT_SCHEMA_FAIL
    return EXIT_OK
