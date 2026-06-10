"""Yara Forge bundle wrapper — vendored, content-addressed ruleset.

Where the existing ``wrappers/yara.py`` shells out to the system
``yara`` binary against per-call rule paths, this wrapper drives the
vendored Yara Forge bundle in-process via ``yara-python`` with:

- A content-addressed source layout at
  ``yara/forge/<tag>/yara-forge-rules-core.yar`` plus a
  ``yara/forge/CURRENT -> <tag>`` symlink (see
  ``yara/RELEASE.md.template``).
- A SHA-256 sidecar pin and on-disk compile cache keyed by bundle
  SHA, so multi-host runs amortize the 1.6 MB compile across ``yara``
  invocations.
- A two-``yara.Rules`` strategy: Forge bundle and operator custom
  rules are compiled into separate ``Rules`` objects and scanned
  independently, then match lists are merged in Python. This sidesteps
  the rule-identifier collision class flagged in critic delta C4-P1
  (Forge ships e.g. ``Cobaltstrike_*`` names that already exist in
  ``detectors/yara_rules/``; ``yara.compile`` rejects duplicates).
- Per-match provenance (``bundle_tag``, ``bundle_sha256``,
  ``rule_sha256``) plus per-rule meta passthrough (license, fp_rate,
  author, source_url, description) for the chain-of-custody fields
  that flow into ``report.json`` (W-024 / report_seal extension).

Public API:

    resolve_active_bundle()                         -> Path | None
    verify_bundle_sha256(path)                      -> bool
    compile_bundle(path, *, cache_dir=None)         -> yara.Rules
    scan_target(target, *, bundle, custom_rules,
                min_quality, license_allowlist)     -> list[YaraForgeMatch]

Environment:
    AGENTROPIX_YARA_FORGE_BUNDLE_REF
        Absolute path to a ``.yar`` bundle file. When set, takes
        precedence over the ``yara/forge/CURRENT`` symlink AND over
        the legacy ``AGENTROPIX_YARA_RULES_DIR`` (W-024 critic delta
        C4-P2: new var wins).
    AGENTROPIX_YARA_FORGE_MIN_QUALITY
        Default integer floor for ``meta.fp_rate`` filtering. Read at
        call time only when ``min_quality`` is not provided. Default 75.
    AGENTROPIX_YARA_FORGE_LICENSE_ALLOWLIST
        Comma-separated SPDX list, or the literal ``commercial-safe``
        which expands to ``COMMERCIAL_SAFE_LICENSES``. Empty / unset
        means no license filtering.
    XDG_CACHE_HOME
        Standard XDG cache root; the compile cache lives at
        ``${XDG_CACHE_HOME:-~/.cache}/agentropix-sift/yara-forge/``.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from pathlib import Path

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# SPDX licenses considered safe for commercial in-house use without an
# additional per-rule audit. Forge core mixes these with GPL and
# CC-BY-NC; the license firewall (critic C2-P1) drops matches whose
# meta.license is set and not in the operator's allowlist.
COMMERCIAL_SAFE_LICENSES: frozenset[str] = frozenset(
    {"Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause"}
)

# Repo-relative path to the active-tag symlink; resolved against the
# importing process's current working directory when the env var
# AGENTROPIX_YARA_FORGE_BUNDLE_REF is unset.
_REPO_BUNDLE_SYMLINK = Path("yara/forge/CURRENT/yara-forge-rules-core.yar")
_BUNDLE_FILENAME = "yara-forge-rules-core.yar"
_SHA_SIDECAR_SUFFIX = ".sha256"

_ENV_BUNDLE_REF = "AGENTROPIX_YARA_FORGE_BUNDLE_REF"
_ENV_MIN_QUALITY = "AGENTROPIX_YARA_FORGE_MIN_QUALITY"
_ENV_LICENSE_ALLOWLIST = "AGENTROPIX_YARA_FORGE_LICENSE_ALLOWLIST"


class YaraForgeIntegrityError(RuntimeError):
    """Bundle SHA-256 mismatch against the sidecar pin."""


class YaraForgeCompileError(RuntimeError):
    """Bundle source file failed to compile via ``yara.compile``."""


class YaraForgeMatch(BaseModel):
    """One rule hit on a target.

    ``bundle_tag`` and ``bundle_sha256`` are populated for matches
    sourced from the Forge bundle; for matches sourced from operator
    custom rules they are ``None``. ``rule_sha256`` is the SHA-256 of
    the rule's source text (``rule <name> ... { ... }`` block) — when
    the source parser cannot recover the block it is ``None``.
    """

    rule_name: str
    tags: list[str] = Field(default_factory=list)
    meta: dict[str, str] = Field(default_factory=dict)
    strings: list[str] = Field(default_factory=list)
    bundle_tag: str | None = None
    bundle_sha256: str | None = None
    rule_sha256: str | None = None
    source: str = "forge"  # "forge" | "custom"


# Module-level provenance caches. Keyed by id() of the yara.Rules
# object returned from compile_bundle(). yara.Rules is a C extension
# type and does not (reliably) accept arbitrary attribute assignment,
# so we keep sidecar maps here. id() is stable for the lifetime of
# the object reference; callers that drop their reference and let GC
# free the rules will lose the lookup, which is the desired behaviour.
_BUNDLE_INFO: dict[int, tuple[str | None, str]] = {}
_RULE_SHAS: dict[int, dict[str, str]] = {}


# ---------------------------------------------------------------------------
# Bundle resolution
# ---------------------------------------------------------------------------


def resolve_active_bundle() -> Path | None:
    """Return the active Yara Forge bundle path, or None if unresolved.

    Resolution order (W-024 critic C4-P2: new env var takes precedence
    over the legacy ``AGENTROPIX_YARA_RULES_DIR``, which this resolver
    deliberately does NOT consult):

    1. ``$AGENTROPIX_YARA_FORGE_BUNDLE_REF`` if set and points at an
       existing file.
    2. ``./yara/forge/CURRENT/yara-forge-rules-core.yar`` if the
       symlink resolves to an existing file.
    3. ``None``.
    """
    override = os.environ.get(_ENV_BUNDLE_REF, "").strip()
    if override:
        p = Path(override)
        if p.is_file():
            return p
        logger.warning(
            "%s=%s but file does not exist; falling back to symlink",
            _ENV_BUNDLE_REF,
            override,
        )

    candidate = _REPO_BUNDLE_SYMLINK
    if candidate.is_file():
        return candidate
    return None


def verify_bundle_sha256(bundle_path: Path) -> bool:
    """Verify ``bundle_path`` against its ``.sha256`` sidecar.

    Strict: any mismatch raises ``YaraForgeIntegrityError``. A missing
    sidecar also raises (refusing to silently scan an unpinned
    bundle). Returns ``True`` on a match.
    """
    bundle_path = Path(bundle_path)
    sidecar = bundle_path.with_suffix(bundle_path.suffix + _SHA_SIDECAR_SUFFIX)
    if not sidecar.is_file():
        raise YaraForgeIntegrityError(
            f"missing sha256 sidecar for {bundle_path} (expected {sidecar})"
        )
    expected = sidecar.read_text(encoding="utf-8").strip().split()[0].lower()
    actual = _sha256_file(bundle_path)
    if expected != actual:
        raise YaraForgeIntegrityError(
            f"bundle hash mismatch for {bundle_path}: "
            f"sidecar={expected} actual={actual}"
        )
    return True


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _bundle_tag_from_path(bundle_path: Path) -> str | None:
    """Return the parent directory name of ``bundle_path``.

    For the canonical layout ``yara/forge/<tag>/yara-forge-rules-core.yar``
    this is the upstream release tag. For the env-override case where a
    caller points at an arbitrary file path we still return the parent
    dir name for traceability; callers that need stricter semantics
    should set the path to the canonical layout.
    """
    try:
        return bundle_path.resolve().parent.name or None
    except OSError:
        return bundle_path.parent.name or None


# ---------------------------------------------------------------------------
# Compile + cache
# ---------------------------------------------------------------------------


def _default_cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME", "").strip()
    if base:
        root = Path(base)
    else:
        root = Path.home() / ".cache"
    return root / "agentropix-sift" / "yara-forge"


def compile_bundle(
    bundle_path: Path,
    *,
    cache_dir: Path | None = None,
) -> "yara.Rules":  # noqa: F821 — forward ref to optional yara module
    """Compile ``bundle_path`` (Forge or custom) into a ``yara.Rules``.

    The compile result is cached on disk via ``yara.save()``, keyed by
    the SHA-256 of the source bundle. A second call with the same
    bundle skips the parser and loads the saved rules with
    ``yara.load()``. Returns the compiled rules.

    Side effect: registers per-rule SHA-256 and bundle provenance in
    module-level maps keyed by ``id(rules)`` so ``scan_target`` can
    decorate matches.
    """
    import yara  # local import — yara-python is an optional runtime dep

    bundle_path = Path(bundle_path)
    if not bundle_path.is_file():
        raise FileNotFoundError(f"bundle not found: {bundle_path}")

    bundle_sha = _sha256_file(bundle_path)
    bundle_tag = _bundle_tag_from_path(bundle_path)

    cache_root = Path(cache_dir) if cache_dir is not None else _default_cache_dir()
    cache_root.mkdir(parents=True, exist_ok=True)
    cache_file = cache_root / f"{bundle_sha}.compiled"

    rules: yara.Rules
    if cache_file.is_file():
        try:
            rules = yara.load(str(cache_file))
            logger.debug("yara_forge: loaded compiled cache %s", cache_file)
        except yara.Error as exc:
            logger.warning(
                "yara_forge: compile cache %s unreadable (%s); recompiling",
                cache_file,
                exc,
            )
            rules = _compile_and_save(bundle_path, cache_file)
    else:
        rules = _compile_and_save(bundle_path, cache_file)

    _BUNDLE_INFO[id(rules)] = (bundle_tag, bundle_sha)
    _RULE_SHAS[id(rules)] = _extract_rule_shas(bundle_path)
    return rules


def _compile_and_save(bundle_path: Path, cache_file: Path) -> "yara.Rules":  # noqa: F821
    import yara

    try:
        rules = yara.compile(filepath=str(bundle_path))
    except yara.SyntaxError as exc:
        raise YaraForgeCompileError(
            f"bundle compile failed: {bundle_path}: {exc}"
        ) from exc
    try:
        rules.save(str(cache_file))
    except yara.Error as exc:
        # Cache is best-effort; surface the error but keep rules.
        logger.warning(
            "yara_forge: failed to save compile cache %s: %s", cache_file, exc
        )
    return rules


# ---------------------------------------------------------------------------
# Per-rule SHA-256 source extraction
# ---------------------------------------------------------------------------

# Captures the start of a rule definition: ``rule NAME`` with optional
# leading ``private``/``global`` qualifiers and optional ``: tag1 tag2``
# tag list before the body. We anchor to a word boundary on ``rule`` so
# we don't match rule references inside conditions.
_RULE_HEAD_RE = re.compile(
    r"""(?:^|[\s;])
    (?P<head>
        (?:private\s+)?
        (?:global\s+)?
        rule\s+
        (?P<name>[A-Za-z_][A-Za-z_0-9]*)
        (?:\s*:\s*[A-Za-z_][\w\s]*)?
        \s*\{
    )
    """,
    re.VERBOSE,
)


def _extract_rule_shas(bundle_path: Path) -> dict[str, str]:
    """Parse a YARA source file and return ``{rule_name: sha256(source)}``.

    Best-effort: skips ``"..."`` strings and ``// ...`` / ``/* ... */``
    comments while tracking brace nesting, so braces inside hex strings
    or comments don't terminate a rule body prematurely. On parse
    failure for an individual rule we omit it from the map; missing
    entries surface as ``rule_sha256=None`` on the match.
    """
    try:
        text = bundle_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.warning("yara_forge: cannot read %s for rule SHAs: %s", bundle_path, exc)
        return {}

    out: dict[str, str] = {}
    for m in _RULE_HEAD_RE.finditer(text):
        name = m.group("name")
        # Find the start of the ``rule`` keyword inside the matched group.
        head_start = m.start("head")
        body_open = m.end()  # position right after the opening '{'
        end = _find_matching_brace(text, body_open)
        if end is None:
            continue
        block = text[head_start:end + 1]
        out[name] = hashlib.sha256(block.encode("utf-8")).hexdigest()
    return out


def _find_matching_brace(text: str, start: int) -> int | None:
    """Return index of the ``}`` that closes the brace whose ``{`` lives
    immediately before ``start``.

    Tracks string and comment context so that braces inside ``"..."``,
    ``// ...`` line comments, or ``/* ... */`` block comments do not
    perturb the depth counter. ``{`` and ``}`` are the only nesting
    characters in YARA source aside from those.
    """
    depth = 1
    i = start
    n = len(text)
    while i < n:
        c = text[i]
        if c == '"':
            i += 1
            while i < n:
                if text[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                if text[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        if c == "/" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "/":
                i = text.find("\n", i + 2)
                if i == -1:
                    return None
                i += 1
                continue
            if nxt == "*":
                end = text.find("*/", i + 2)
                if end == -1:
                    return None
                i = end + 2
                continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------


def _resolve_min_quality(min_quality: int | None) -> int:
    if min_quality is not None:
        return int(min_quality)
    raw = os.environ.get(_ENV_MIN_QUALITY, "").strip()
    if not raw:
        return 75
    try:
        return int(raw)
    except ValueError:
        logger.warning(
            "%s=%r not an integer; using default 75", _ENV_MIN_QUALITY, raw
        )
        return 75


def _resolve_license_allowlist(
    license_allowlist: frozenset[str] | None,
) -> frozenset[str] | None:
    if license_allowlist is not None:
        return frozenset(license_allowlist)
    raw = os.environ.get(_ENV_LICENSE_ALLOWLIST, "").strip()
    if not raw:
        return None
    if raw == "commercial-safe":
        return COMMERCIAL_SAFE_LICENSES
    return frozenset(item.strip() for item in raw.split(",") if item.strip())


def _meta_int(meta: dict, key: str) -> int | None:
    v = meta.get(key)
    if v is None:
        return None
    if isinstance(v, bool):
        # YARA exposes booleans separately from ints; unwrap defensively.
        return int(v)
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        try:
            return int(v.strip())
        except ValueError:
            return None
    return None


def _stringify_match_strings(raw_strings) -> list[str]:
    """Render yara-python's match strings list across versions.

    yara-python <4.3 returns ``list[tuple[int, str, bytes]]``. yara-python
    >=4.3 returns ``list[StringMatch]`` with an ``.instances`` collection
    of ``StringMatchInstance`` (offset + matched_data). We coerce both
    to ``["0x<hex>:<id>:<repr>", ...]`` so downstream readers see one
    shape.
    """
    out: list[str] = []
    for entry in raw_strings or []:
        if isinstance(entry, tuple) and len(entry) == 3:
            offset, ident, data = entry
            try:
                rendered = data.decode("utf-8", errors="replace")
            except AttributeError:
                rendered = str(data)
            out.append(f"0x{offset:x}:{ident}:{rendered}")
            continue
        # 4.3+ StringMatch: .identifier, .instances[*].offset/.matched_data
        ident = getattr(entry, "identifier", "?")
        instances = getattr(entry, "instances", None) or []
        if not instances:
            out.append(f"0x0:{ident}:")
            continue
        for inst in instances:
            offset = getattr(inst, "offset", 0)
            data = getattr(inst, "matched_data", b"")
            try:
                rendered = data.decode("utf-8", errors="replace")
            except AttributeError:
                rendered = str(data)
            out.append(f"0x{offset:x}:{ident}:{rendered}")
    return out


def _build_match(
    raw,
    *,
    source: str,
    bundle_tag: str | None,
    bundle_sha256: str | None,
    rule_sha: str | None,
) -> YaraForgeMatch:
    meta_raw = getattr(raw, "meta", {}) or {}
    # YARA meta values may be int/bool/str — stringify for the schema's
    # str-valued dict while preserving the typed copy for filters.
    meta_str = {k: _meta_to_str(v) for k, v in meta_raw.items()}
    return YaraForgeMatch(
        rule_name=getattr(raw, "rule", ""),
        tags=list(getattr(raw, "tags", []) or []),
        meta=meta_str,
        strings=_stringify_match_strings(getattr(raw, "strings", None)),
        bundle_tag=bundle_tag,
        bundle_sha256=bundle_sha256,
        rule_sha256=rule_sha,
        source=source,
    )


def _meta_to_str(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _passes_min_quality(meta_raw: dict, min_quality: int) -> bool:
    fp = _meta_int(meta_raw, "fp_rate")
    if fp is None:
        # Treat absent fp_rate as 100 (assume high quality) per critic
        # delta C3-P0: filtering must not drop legacy / custom rules
        # that don't carry fp_rate metadata.
        return True
    return fp >= min_quality


def _passes_license_allowlist(
    meta_raw: dict, allowlist: frozenset[str] | None
) -> bool:
    if allowlist is None:
        return True
    lic = meta_raw.get("license")
    if lic is None:
        # No license metadata -> let the match through. Operators who
        # need a strict-deny posture can pre-process bundles to ensure
        # every rule carries a license tag.
        return True
    return _meta_to_str(lic) in allowlist


def scan_target(
    target: str | Path,
    *,
    bundle: "yara.Rules" | None = None,  # noqa: F821
    custom_rules: "yara.Rules" | None = None,  # noqa: F821
    min_quality: int | None = None,
    license_allowlist: frozenset[str] | None = None,
) -> list[YaraForgeMatch]:
    """Scan ``target`` against the Forge bundle and/or custom rules.

    Both ``bundle`` and ``custom_rules`` are independently compiled
    ``yara.Rules`` objects (see ``compile_bundle``); the dual-Rules
    strategy avoids the rule-identifier collision class that
    ``yara.compile(filepaths={...})`` would raise on duplicate rule
    names across sources (critic delta C4-P1).

    Filters:
        - ``min_quality``: drop matches whose ``meta.fp_rate < min_quality``.
          ``None`` reads ``$AGENTROPIX_YARA_FORGE_MIN_QUALITY`` (default 75).
          Matches with no ``fp_rate`` meta key pass through.
        - ``license_allowlist``: drop matches whose ``meta.license`` is
          set and not in the allowlist. ``None`` reads
          ``$AGENTROPIX_YARA_FORGE_LICENSE_ALLOWLIST``; the literal
          ``commercial-safe`` expands to ``COMMERCIAL_SAFE_LICENSES``.
          Matches with no ``license`` meta key pass through.
    """
    target_path = Path(target)
    if not target_path.exists():
        raise FileNotFoundError(f"target not found: {target_path}")

    quality_floor = _resolve_min_quality(min_quality)
    allowlist = _resolve_license_allowlist(license_allowlist)

    out: list[YaraForgeMatch] = []

    if bundle is not None:
        bundle_tag, bundle_sha = _BUNDLE_INFO.get(id(bundle), (None, None))
        rule_sha_map = _RULE_SHAS.get(id(bundle), {})
        for raw in bundle.match(filepath=str(target_path)):
            meta_raw = getattr(raw, "meta", {}) or {}
            if not _passes_min_quality(meta_raw, quality_floor):
                continue
            if not _passes_license_allowlist(meta_raw, allowlist):
                continue
            out.append(
                _build_match(
                    raw,
                    source="forge",
                    bundle_tag=bundle_tag,
                    bundle_sha256=bundle_sha,
                    rule_sha=rule_sha_map.get(getattr(raw, "rule", "")),
                )
            )

    if custom_rules is not None:
        custom_tag, custom_sha = _BUNDLE_INFO.get(id(custom_rules), (None, None))
        custom_rule_shas = _RULE_SHAS.get(id(custom_rules), {})
        for raw in custom_rules.match(filepath=str(target_path)):
            meta_raw = getattr(raw, "meta", {}) or {}
            # Quality / license filters apply uniformly; rules without
            # the meta keys pass through (custom rules typically lack
            # fp_rate / license tags).
            if not _passes_min_quality(meta_raw, quality_floor):
                continue
            if not _passes_license_allowlist(meta_raw, allowlist):
                continue
            out.append(
                _build_match(
                    raw,
                    source="custom",
                    bundle_tag=custom_tag,
                    bundle_sha256=custom_sha,
                    rule_sha=custom_rule_shas.get(getattr(raw, "rule", "")),
                )
            )

    return out


__all__ = [
    "COMMERCIAL_SAFE_LICENSES",
    "YaraForgeCompileError",
    "YaraForgeIntegrityError",
    "YaraForgeMatch",
    "compile_bundle",
    "resolve_active_bundle",
    "scan_target",
    "verify_bundle_sha256",
]
