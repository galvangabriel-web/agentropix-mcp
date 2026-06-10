"""YARAHuntAgent — signature-based Cobalt Strike stager detection.

Closes W-052-T2: detects Cobalt Strike beacon stagers via YARA signature
matching. The agent:

1. Compiles all `.yar` rules under the configured rules directory once
   per process (cached on first investigation).
2. Walks the evidence target (E01 image, mounted directory, or memory
   dump) and applies the rule set to suspect files (Prefetch, AppData,
   System32, Temp, mounted PE/DLL files).
3. Emits Findings keyed on the matching rule name + file path. Confidence
   is rule-specific (high-confidence beacon rules → 0.95, generic patterns
   → 0.75).

The agent is deliberately defensive about its inputs. A missing rules
directory, a corrupt rule file, or a YARA library that's not installed
all degrade gracefully: emit a single low-confidence informational
Finding describing the degradation and continue. Production triages
should never abort because the YARA toolchain has a hiccup.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agentropix_mcp.agents._base import Finding, SwarmAgent
from agentropix_mcp._env import get_float, get_int
from agentropix_mcp.wrappers.yara_forge import (
    YaraForgeCompileError,
    YaraForgeIntegrityError,
    compile_bundle,
    resolve_active_bundle,
    scan_target,
    verify_bundle_sha256,
)

if TYPE_CHECKING:
    pass

# W-024 Phase B.4: Yara Forge upstream + default fp_rate floor for the
# `yara_forge.bundle_active` provenance finding. The agent will scan
# with the Forge bundle in addition to the legacy custom rules dir
# whenever the bundle resolves and verifies; on verify/compile failure
# the agent falls back to legacy-only and emits a `yara_forge.skipped`
# finding carrying the failure reason.
_YARA_FORGE_SOURCE_URL = "https://github.com/YARAHQ/yara-forge"
_DEFAULT_FORGE_MIN_QUALITY = 75

logger = logging.getLogger(__name__)

# Default YARA scan budgets — chosen to keep an E2E DC E01 triage under
# the 10-minute wall-clock (FR-W052-NFR-003). Operators can override via
# `AGENTROPIX_YARA_*` env vars; floor/ceiling guards are enforced.
_DEFAULT_SCAN_TIMEOUT_S = 60
_DEFAULT_MAX_FILES_PER_DIR = 500
_DEFAULT_MAX_FILE_SIZE_MB = 50

# Files we YARA-scan when a directory is provided. Memory images are
# scanned directly (no walk). The patterns are conservative — Cobalt
# Strike stagers land in Prefetch, AppData/Local/Temp, System32, and
# the operator's `Downloads`/`Temp` folders.
_DEFAULT_SCAN_TARGETS = (
    "*.exe",
    "*.dll",
    "*.pf",          # Prefetch files
    "*.bin",
    "*.tmp",
    "*.dat",
)


def _default_rules_dir() -> Path:
    """Resolve the bundled YARA rules directory.

    Honours `AGENTROPIX_YARA_RULES_DIR` for operator overrides; falls
    back to the package-bundled rules under ``detectors/yara_rules/``.
    """
    override = os.environ.get("AGENTROPIX_YARA_RULES_DIR", "").strip()
    if override:
        return Path(override).expanduser().resolve()
    return Path(__file__).resolve().parent / "yara_rules"


def _try_import_yara() -> Any:
    """Import yara-python lazily.

    Returns the module on success, ``None`` on failure. We don't promote
    yara-python to a hard dependency because the rest of agentropix-sift
    is functional without it — a missing YARA install means W-052-T2
    findings won't fire, but every other agent (memory, timeline, etc.)
    is unaffected.
    """
    try:
        import yara  # type: ignore[import-not-found]

        return yara
    except ImportError as exc:
        logger.warning(
            "yara-python not importable; YARAHuntAgent will report degraded (%s). "
            "Install hint: cd %s && uv pip install yara-python  "
            "(see W-163 in docs/SIFT-WEAKNESSES.md for the lockfile-drift root cause).",
            exc,
            "pip install 'agentropix-mcp[forensics]'",
        )
        return None


def _walk_targets(root: Path, max_files: int, max_file_size_mb: int) -> Iterable[Path]:
    """Yield candidate files for YARA scanning.

    Bounded by ``max_files`` (per-directory walk cap) and ``max_file_size_mb``
    (per-file size cap). Larger limits trade scan time for coverage; both
    are tunable via env. The walk skips symlinks to avoid traversing
    out-of-sandbox paths (Thymus catches those at the MCP boundary, but
    defence-in-depth here means we never queue a symlinked file in the
    first place).
    """
    if root.is_file():
        if root.stat().st_size <= max_file_size_mb * 1024 * 1024:
            yield root
        return

    if not root.is_dir():
        return

    yielded = 0
    max_bytes = max_file_size_mb * 1024 * 1024
    for pattern in _DEFAULT_SCAN_TARGETS:
        for candidate in root.rglob(pattern):
            if yielded >= max_files:
                return
            try:
                if candidate.is_symlink() or not candidate.is_file():
                    continue
                if candidate.stat().st_size > max_bytes:
                    continue
            except OSError:
                continue
            yielded += 1
            yield candidate


class YARAHuntAgent(SwarmAgent):
    """Cobalt Strike stager detection via YARA rules.

    W-052-T2 closure: the agent runs a vendored YARA rule set against
    candidate files in the evidence target. Each rule match becomes a
    high-confidence Finding (technique=T1055) carrying the rule name and
    file path as evidence — exactly the tokens that ground-truth #2
    needs (RUNDLL32 + rule name) for cohit≥2 against TimelineAgent's
    LOLBin emissions.

    The agent caches compiled rules in a process-local dict so repeated
    investigations don't re-parse the rule set. Cache is keyed by the
    rules directory mtime; rule edits invalidate the cache automatically.
    """

    name = "yara_hunt"
    completion_promise = "YARA_HUNT_COMPLETE"

    _rules_cache: dict[tuple[str, float], Any] = {}

    async def investigate(self, image: Path) -> list[Finding]:
        findings: list[Finding] = []

        yara = _try_import_yara()
        if yara is None:
            findings.append(
                Finding(
                    source="yara_hunt.degraded",
                    confidence=0.30,
                    description=(
                        "YARAHuntAgent degraded: yara-python not installed. "
                        "Install via `pip install yara-python` to enable T2 detection."
                    ),
                    evidence="missing_dependency=yara-python",
                    timestamp=Finding.now(),
                    mitre_attack="",
                )
            )
            return findings

        rules_dir = _default_rules_dir()
        legacy_rules = self._load_rules(yara, rules_dir, findings)
        if legacy_rules is None:
            return findings

        # W-024 Phase B.4: try Forge bundle. On verify/compile failure
        # we emit `yara_forge.skipped` and continue legacy-only; on
        # success we emit `yara_forge.bundle_active` and scan with both.
        forge_rules = self._load_forge_bundle(findings)

        scan_timeout = get_int(
            "AGENTROPIX_YARA_SCAN_TIMEOUT_S",
            _DEFAULT_SCAN_TIMEOUT_S,
            floor=5,
            ceiling=600,
        )
        max_files = get_int(
            "AGENTROPIX_YARA_MAX_FILES",
            _DEFAULT_MAX_FILES_PER_DIR,
            floor=10,
            ceiling=10000,
        )
        max_file_size_mb = get_int(
            "AGENTROPIX_YARA_MAX_FILE_SIZE_MB",
            _DEFAULT_MAX_FILE_SIZE_MB,
            floor=1,
            ceiling=2048,
        )
        confidence_floor = get_float(
            "AGENTROPIX_YARA_CONFIDENCE_FLOOR",
            0.75,
            floor=0.0,
            ceiling=1.0,
        )
        forge_min_quality = get_int(
            "AGENTROPIX_YARA_FORGE_MIN_QUALITY",
            _DEFAULT_FORGE_MIN_QUALITY,
            floor=0,
            ceiling=100,
        )

        scan_root = self._resolve_scan_root(image, findings)
        if scan_root is None:
            # W-NEW-6: _resolve_scan_root has already appended a specific
            # skip-reason Finding (e.g. yara_hunt.e01_unmounted_skip) when
            # it knew why. If it didn't, append the generic skip.
            if not any(
                f.source.startswith("yara_hunt.") and "skip" in f.source
                for f in findings
            ):
                findings.append(
                    Finding(
                        source="yara_hunt.skipped",
                        confidence=0.20,
                        description=(
                            f"YARAHuntAgent skipped: cannot resolve scannable target from {image}"
                        ),
                        evidence=f"image={image}",
                        timestamp=Finding.now(),
                    )
                )
            return findings

        deadline = time.monotonic() + scan_timeout
        files_scanned = 0
        timed_out = False
        for candidate in _walk_targets(scan_root, max_files, max_file_size_mb):
            if time.monotonic() >= deadline:
                timed_out = True
                break
            files_scanned += 1

            # Legacy custom rules: keep the positional match() API so
            # existing test fakes (`_FakeRules.match(self, _path)`) and
            # future operator-supplied rules dirs continue to work.
            try:
                legacy_matches = legacy_rules.match(str(candidate))
            except Exception as exc:  # noqa: BLE001 — yara errors aren't a fixed type
                logger.debug("YARA scan failed for %s: %s", candidate, exc)
                legacy_matches = []
            for match in legacy_matches:
                rule_name = getattr(match, "rule", "<unknown>")
                tags = list(getattr(match, "tags", []) or [])
                meta = dict(getattr(match, "meta", {}) or {})
                findings.append(
                    self._build_match_finding(
                        rule_name=rule_name,
                        tags=tags,
                        meta=meta,
                        candidate=candidate,
                        bundle_tag=None,
                        bundle_sha256=None,
                        rule_sha256=None,
                        confidence_floor=confidence_floor,
                    )
                )

            # Forge bundle: route through scan_target so we get the
            # license + fp_rate filters and the per-rule SHA-256 the
            # wrapper extracts at compile time. ``custom_rules=None``
            # so the legacy rules aren't double-scanned.
            if forge_rules is not None:
                try:
                    forge_matches = scan_target(
                        candidate,
                        bundle=forge_rules,
                        custom_rules=None,
                        min_quality=forge_min_quality,
                        license_allowlist=None,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.debug(
                        "YARA Forge scan_target failed for %s: %s", candidate, exc
                    )
                    forge_matches = []
                for m in forge_matches:
                    findings.append(
                        self._build_match_finding(
                            rule_name=m.rule_name,
                            tags=list(m.tags),
                            meta=dict(m.meta),
                            candidate=candidate,
                            bundle_tag=m.bundle_tag,
                            bundle_sha256=m.bundle_sha256,
                            rule_sha256=m.rule_sha256,
                            confidence_floor=confidence_floor,
                        )
                    )

        if timed_out:
            findings.append(
                Finding(
                    source="yara_hunt.timeout",
                    confidence=0.40,
                    description=(
                        f"YARA scan timed out after {scan_timeout}s "
                        f"(scanned {files_scanned} files); partial results preserved"
                    ),
                    evidence=f"timeout={scan_timeout}s files_scanned={files_scanned}",
                    timestamp=Finding.now(),
                )
            )

        if files_scanned == 0:
            findings.append(
                Finding(
                    source="yara_hunt.empty",
                    confidence=0.20,
                    description=(
                        f"YARAHuntAgent found no scannable files under {scan_root}"
                    ),
                    evidence=f"scan_root={scan_root}",
                    timestamp=Finding.now(),
                )
            )

        return findings

    def _resolve_scan_root(
        self, image: Path, findings: list[Finding] | None = None
    ) -> Path | None:
        """Pick the directory or file YARA should scan.

        Strategy:
          * Memory dumps (.img/.mem/.dmp) → scan the dump file directly.
          * Disk E01 images → check AGENTROPIX_YARA_MOUNT_PREFIX env var; if set
            and valid, use it; otherwise emit yara_hunt.e01_unmounted_skip
            and return None.
          * Plain directories → scan recursively.

        W-NEW-6 (2026-05-12): for E01 images with no mount prefix, emit an
        explicit ``yara_hunt.e01_unmounted_skip`` Finding into ``findings``
        (when provided) so the gap surfaces in the report instead of being
        a silent log line. This makes a YARA-only IOC regression detectable
        before it bites a real triage. (``findings`` is optional for
        backwards-compatibility with callers that don't pass it.)
        """
        import os

        if not image.exists():
            return None

        # E01 forensic images need explicit mount prefix
        if image.suffix.lower() == ".e01":
            mount_prefix = os.environ.get("AGENTROPIX_YARA_MOUNT_PREFIX", "").strip()
            if mount_prefix and Path(mount_prefix).is_dir():
                return Path(mount_prefix)
            # W-NEW-6: explicit skip-reason Finding so the report shows the gap.
            reason_detail = (
                "unset"
                if not mount_prefix
                else f"invalid path={mount_prefix!r} (not a directory)"
            )
            logger.warning(
                "E01 image %s but AGENTROPIX_YARA_MOUNT_PREFIX %s; skipping YARA",
                image,
                reason_detail,
            )
            if findings is not None:
                findings.append(
                    Finding(
                        source="yara_hunt.e01_unmounted_skip",
                        confidence=0.30,
                        description=(
                            f"YARA scan skipped for E01 image {image.name}: "
                            f"AGENTROPIX_YARA_MOUNT_PREFIX {reason_detail}. "
                            "Mount the E01 (ewfmount + filesystem mount) and set "
                            "AGENTROPIX_YARA_MOUNT_PREFIX to the mounted root, "
                            "or document the coverage gap in the case ledger."
                        ),
                        evidence=(
                            f"image={image} mount_prefix={mount_prefix!r} "
                            f"resolved={'dir' if mount_prefix and Path(mount_prefix).is_dir() else 'invalid'}"
                        ),
                        timestamp=Finding.now(),
                    )
                )
            return None

        # Regular files or directories
        if image.is_file():
            return image
        if image.is_dir():
            return image
        return None

    def _load_forge_bundle(self, findings: list[Finding]) -> Any | None:
        """Resolve, verify, and compile the active Yara Forge bundle.

        Returns the compiled ``yara.Rules`` on success (after appending a
        ``yara_forge.bundle_active`` provenance finding), or ``None`` on
        no-bundle / verify / compile failure. Verify and compile failures
        emit ``yara_forge.skipped`` findings so the operator sees in the
        report why the dual-Rules wiring fell back to legacy-only.
        """
        forge_path = resolve_active_bundle()
        if forge_path is None:
            return None

        try:
            verify_bundle_sha256(forge_path)
        except YaraForgeIntegrityError as exc:
            findings.append(
                Finding(
                    source="yara_forge.skipped",
                    confidence=0.30,
                    description=f"YARA Forge bundle skipped: sha_mismatch ({exc})",
                    evidence=(
                        f"path={forge_path} reason=sha_mismatch error={exc}"
                    ),
                    evidence_dict={
                        "reason": "sha_mismatch",
                        "path": str(forge_path),
                    },
                    timestamp=Finding.now(),
                )
            )
            return None
        except OSError as exc:
            findings.append(
                Finding(
                    source="yara_forge.skipped",
                    confidence=0.30,
                    description=f"YARA Forge bundle skipped: io_error ({exc})",
                    evidence=f"path={forge_path} reason=io_error error={exc}",
                    evidence_dict={"reason": "io_error", "path": str(forge_path)},
                    timestamp=Finding.now(),
                )
            )
            return None

        try:
            forge_rules = compile_bundle(forge_path)
        except (YaraForgeCompileError, FileNotFoundError, OSError) as exc:
            findings.append(
                Finding(
                    source="yara_forge.skipped",
                    confidence=0.30,
                    description=f"YARA Forge bundle skipped: compile_error ({exc})",
                    evidence=(
                        f"path={forge_path} reason=compile_error error={exc}"
                    ),
                    evidence_dict={
                        "reason": "compile_error",
                        "path": str(forge_path),
                    },
                    timestamp=Finding.now(),
                )
            )
            return None
        except Exception as exc:  # noqa: BLE001 — yara errors aren't a fixed type
            findings.append(
                Finding(
                    source="yara_forge.skipped",
                    confidence=0.30,
                    description=f"YARA Forge bundle skipped: compile_error ({exc})",
                    evidence=(
                        f"path={forge_path} reason=compile_error error={exc}"
                    ),
                    evidence_dict={
                        "reason": "compile_error",
                        "path": str(forge_path),
                    },
                    timestamp=Finding.now(),
                )
            )
            return None

        # verify_bundle_sha256 already proved the sidecar matches; read
        # the canonical sha and the parent-dir tag for the provenance
        # finding the orchestrator surfaces in `report.json`.
        sidecar = forge_path.with_suffix(forge_path.suffix + ".sha256")
        try:
            bundle_sha = (
                sidecar.read_text(encoding="utf-8").strip().split()[0].lower()
            )
        except OSError:
            bundle_sha = ""
        try:
            tag = forge_path.resolve().parent.name or ""
        except OSError:
            tag = forge_path.parent.name or ""

        forge_min_quality = get_int(
            "AGENTROPIX_YARA_FORGE_MIN_QUALITY",
            _DEFAULT_FORGE_MIN_QUALITY,
            floor=0,
            ceiling=100,
        )
        sha_preview = bundle_sha[:16] + "..." if bundle_sha else "(unknown)"
        findings.append(
            Finding(
                # Status announcement (bundle loaded), not a detection on the
                # image. Keep at confidence=0.0 so the FP gate in
                # tests/integration/test_e2e_dc_recall.py::test_no_false_positives_on_clean_image
                # does not count it as a hallucination. Mirrors the
                # yara_hunt.rule_error pattern (~ line 619) and the
                # MemoryAgent / InjectionDetector "skipped" findings.
                source="yara_forge.bundle_active",
                confidence=0.0,
                description=f"YARA Forge bundle active: tag={tag} sha256={sha_preview}",
                evidence=(
                    f"tag={tag} sha256={bundle_sha} path={forge_path} "
                    f"fp_threshold={forge_min_quality}"
                ),
                evidence_dict={
                    "tag": tag,
                    "sha256": bundle_sha,
                    "source_url": _YARA_FORGE_SOURCE_URL,
                    "fp_threshold": forge_min_quality,
                    "license_allowlist": None,
                },
                timestamp=Finding.now(),
            )
        )
        return forge_rules

    def _build_match_finding(
        self,
        *,
        rule_name: str,
        tags: list[str],
        meta: dict[str, Any],
        candidate: Path,
        bundle_tag: str | None,
        bundle_sha256: str | None,
        rule_sha256: str | None,
        confidence_floor: float,
    ) -> Finding:
        """Build a `yara_hunt.match` finding with the per-finding
        ``yara_rule`` metadata sub-block.

        The finding shape is identical for legacy and Forge matches; the
        ``bundle_tag`` / ``bundle_sha256`` / ``rule_sha256`` fields are
        ``None`` for legacy custom rules and populated for Forge rules.
        """
        meta_confidence = self._meta_confidence(meta, confidence_floor)
        yara_rule_block: dict[str, Any] = {
            "name": rule_name,
            "tags": list(tags),
            "author": meta.get("author"),
            "source_url": meta.get("source_url") or meta.get("source"),
            "license": meta.get("license"),
            "fp_rate": (
                meta.get("fp_rate") or meta.get("quality") or meta.get("score")
            ),
            "rule_sha256": rule_sha256,
            "bundle_tag": bundle_tag,
            "bundle_sha256": bundle_sha256,
        }
        return Finding(
            source="yara_hunt.match",
            confidence=meta_confidence,
            description=(
                f"YARA match: rule={rule_name} "
                f"file={candidate.name} tags={','.join(tags)}"
            ),
            evidence=(
                f"rule={rule_name} path={candidate} "
                f"tags={','.join(tags)} meta={dict(meta)}"
            ),
            evidence_dict={
                "rule": rule_name,
                "path": str(candidate),
                "tags": list(tags),
                "yara_rule": yara_rule_block,
            },
            mitre_attack=str(meta.get("mitre", "T1055")),
            timestamp=Finding.now(),
        )

    def _load_rules(
        self,
        yara: Any,
        rules_dir: Path,
        findings: list[Finding],
    ) -> Any:
        """Compile (and cache) all `.yar` files under ``rules_dir``."""
        if not rules_dir.exists() or not rules_dir.is_dir():
            findings.append(
                Finding(
                    source="yara_hunt.no_rules",
                    confidence=0.30,
                    description=(
                        f"YARAHuntAgent has no rules directory at {rules_dir}; "
                        "set AGENTROPIX_YARA_RULES_DIR or install bundled rules"
                    ),
                    evidence=f"rules_dir={rules_dir}",
                    timestamp=Finding.now(),
                )
            )
            return None

        # Cache key includes mtime so rule edits invalidate cache automatically.
        try:
            mtime = max(
                (p.stat().st_mtime for p in rules_dir.rglob("*.yar")),
                default=0.0,
            )
        except OSError:
            mtime = 0.0
        cache_key = (str(rules_dir), mtime)
        cached = self._rules_cache.get(cache_key)
        if cached is not None:
            return cached

        rule_files = sorted(rules_dir.rglob("*.yar"))
        if not rule_files:
            findings.append(
                Finding(
                    source="yara_hunt.no_rules",
                    confidence=0.30,
                    description=f"YARAHuntAgent rules directory empty: {rules_dir}",
                    evidence=f"rules_dir={rules_dir}",
                    timestamp=Finding.now(),
                )
            )
            return None

        # `yara.compile` accepts {namespace: filepath}. Namespace each file
        # by its basename so error messages identify the rule on conflict.
        filepaths = {p.stem: str(p) for p in rule_files}
        try:
            compiled = yara.compile(filepaths=filepaths)
        except Exception as exc:  # noqa: BLE001
            # W-168: a compile failure takes the entire YARA scanning
            # surface offline.  Surface it via logger.warning so the
            # operator still sees it; emit the Finding at confidence=0.0
            # so the FP gate doesn't count it as a hallucination.
            # tests/unit/detectors/test_yara_rules_compile.py guards
            # against this path firing in production.
            logger.warning(
                "YARA rule compilation failed in %s: %s — "
                "YARAHuntAgent will produce no detections this run",
                rules_dir,
                exc,
            )
            findings.append(
                Finding(
                    source="yara_hunt.rule_error",
                    confidence=0.0,
                    description=f"YARA rule compilation failed: {exc}",
                    evidence=f"rules_dir={rules_dir} error={exc}",
                    timestamp=Finding.now(),
                )
            )
            return None

        self._rules_cache[cache_key] = compiled
        return compiled

    @staticmethod
    def _meta_confidence(meta: dict[str, Any], floor: float) -> float:
        """Translate YARA rule meta `confidence` (high|med|low) to a float."""
        raw = str(meta.get("confidence", "")).strip().lower()
        mapping = {"high": 0.95, "medium": 0.85, "med": 0.85, "low": 0.75}
        if raw in mapping:
            return max(floor, mapping[raw])
        # Fallback: numeric meta confidence (e.g. confidence = "0.92").
        try:
            return max(floor, min(1.0, float(meta.get("confidence", floor))))
        except (TypeError, ValueError):
            return floor
