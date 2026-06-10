"""impacket-secretsdump LOCAL wrapper — offline credential triage (W-072 / ADR-014).

vol3 2.27.0 dropped the ``windows.hashdump`` / ``windows.lsadump`` /
``windows.cachedump`` plugins. ADR-014 keeps the upstream pin but
restores credential triage by shelling out to
``impacket-secretsdump.py LOCAL`` against a previously extracted SAM /
SECURITY / SYSTEM hive triple. The wrapper is the offline-parsing arm
of that flow:

* Each hive path is Thymus-policy-checked before the subprocess runs;
  hives must already live under one of the policy-allowed read prefixes
  (``/cases/``, ``/tmp/agentropix-sift-*``, etc.). The agent that
  orchestrates extraction is responsible for landing them there.
* The binary is resolved via ``shutil.which`` against
  ``AGENTROPIX_SECRETSDUMP_TOOL`` (default tries
  ``impacket-secretsdump.py``, then ``secretsdump.py`` — the upstream
  Debian package installs as the latter).
* Output is parsed line-wise into typed Pydantic rows. The format is
  stable across impacket releases since it's the public CLI contract.
* Failure modes are normalised: missing binary → ``RuntimeError`` with
  a ``pip install impacket`` hint; subprocess timeout →
  ``TimeoutError``; malformed output → empty report with
  ``parse_warnings`` populated (the agent emits an unavailable Finding
  in that case rather than crashing the run).
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
from pathlib import Path

from pydantic import BaseModel, Field

from agentropix_mcp.thymus_policy import ThymusEvidencePolicy

logger = logging.getLogger(__name__)

#: Default secretsdump binary names searched on PATH, in order.
DEFAULT_TOOLS = ("impacket-secretsdump.py", "secretsdump.py")
INSTALL_HINT = (
    "impacket-secretsdump.py not found on PATH; "
    "install via `pip install impacket` (>=0.11.0) or set "
    "AGENTROPIX_SECRETSDUMP_TOOL to the absolute binary path"
)


def _resolve_tool() -> str | None:
    """Resolve the secretsdump binary.

    Honours ``AGENTROPIX_SECRETSDUMP_TOOL`` first (operator override —
    if it's an absolute path, it's used verbatim; if it's a bare name,
    PATH lookup applies). Otherwise tries each name in
    :data:`DEFAULT_TOOLS` in order. Returns ``None`` when no candidate
    is found.
    """
    override = os.environ.get("AGENTROPIX_SECRETSDUMP_TOOL", "").strip()
    if override:
        if os.path.isabs(override) and os.access(override, os.X_OK):
            return override
        located = shutil.which(override)
        if located:
            return located
        return None
    for name in DEFAULT_TOOLS:
        located = shutil.which(name)
        if located:
            return located
    return None


class NTLMHashRow(BaseModel):
    """One SAM-derived local-account NTLM hash row."""

    account: str
    rid: int = 0
    ntlm_hash: str = ""
    lm_hash: str = ""


class LSASecret(BaseModel):
    """One LSA secret entry. ``value_hex`` is the raw hex-encoded blob."""

    name: str
    value_hex: str = ""


class MSCacheEntry(BaseModel):
    """One cached domain credential (DCC2 / MSCASHv2)."""

    account: str
    dcc2_hash: str = ""
    domain: str = ""


class CredentialDumpReport(BaseModel):
    """Top-level structured result of a single ``secretsdump LOCAL`` call.

    ``parse_warnings`` is non-empty whenever the parser couldn't make
    sense of impacket's output but the subprocess itself completed
    without error — the calling agent treats that as a "no creds" outcome
    rather than a hard failure.
    """

    sam_hive: str
    security_hive: str = ""
    system_hive: str
    tool: str = "impacket-secretsdump"
    tool_path: str = ""
    return_code: int = 0
    ntlm_hashes: list[NTLMHashRow] = Field(default_factory=list)
    lsa_secrets: list[LSASecret] = Field(default_factory=list)
    cached_domain_creds: list[MSCacheEntry] = Field(default_factory=list)
    parse_warnings: list[str] = Field(default_factory=list)
    raw_stderr: str = ""


_DEFAULT_POLICY = ThymusEvidencePolicy()


def _check_thymus(path: Path, label: str) -> None:
    """Run Thymus ``check_read`` on ``path`` and raise on violation.

    A fresh policy instance is constructed at module load; the agent
    orchestrator can pass paths under any allowed read prefix, including
    auto-detected per-case directories. Raises ``PermissionError`` so
    callers can distinguish a policy reject from a missing-file error.
    """
    violation = _DEFAULT_POLICY.check_read(str(path))
    if violation:
        raise PermissionError(f"Thymus REJECT on {label} hive ({path}): {violation}")


def _parse_secretsdump_output(stdout: str) -> tuple[
    list[NTLMHashRow], list[LSASecret], list[MSCacheEntry], list[str]
]:
    """Split secretsdump LOCAL stdout into typed rows.

    impacket emits sections separated by ``[*]`` banner lines:

      [*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
      Administrator:500:aad3b...:31d6c...:::
      ...
      [*] Dumping cached domain logon information (...)
      DOMAIN.local/svc_user:$DCC2$10240#svc_user#abcdef...
      ...
      [*] Dumping LSA Secrets
      [*] $MACHINE.ACC
       $MACHINE.ACC: 0x0102...
      ...

    The parser is tolerant: any line that doesn't match a known shape is
    silently skipped (parser warnings only fire when the *whole* output
    yielded no rows but had non-banner content — that's the "malformed"
    signal the agent surfaces).
    """
    ntlm: list[NTLMHashRow] = []
    lsa: list[LSASecret] = []
    cache: list[MSCacheEntry] = []
    warnings: list[str] = []

    section: str | None = None
    non_banner_lines = 0

    for raw_line in stdout.splitlines():
        line = raw_line.rstrip()
        if not line:
            continue
        stripped = line.strip()

        # Section banners.
        if stripped.startswith("[*]"):
            lower = stripped.lower()
            if "local sam hashes" in lower:
                section = "sam"
            elif "cached domain logon" in lower:
                section = "cache"
            elif "lsa secrets" in lower:
                section = "lsa"
            elif "cleaning up" in lower or "target system bootkey" in lower:
                section = None
            continue
        if stripped.startswith("[-]") or stripped.startswith("[!]"):
            warnings.append(stripped[:300])
            continue

        non_banner_lines += 1

        if section == "sam":
            # account:rid:lmhash:nthash:::
            parts = stripped.split(":")
            if len(parts) >= 4:
                account = parts[0]
                rid_raw = parts[1]
                lm_hash = parts[2]
                ntlm_hash = parts[3]
                try:
                    rid = int(rid_raw)
                except ValueError:
                    continue
                if not account:
                    continue
                ntlm.append(
                    NTLMHashRow(
                        account=account,
                        rid=rid,
                        ntlm_hash=ntlm_hash,
                        lm_hash=lm_hash,
                    )
                )
        elif section == "cache":
            # DOMAIN.local/svc_user:$DCC2$10240#svc_user#abcdef...
            head, sep, hash_part = stripped.partition(":")
            if not sep or not hash_part:
                continue
            domain = ""
            account = head
            if "/" in head:
                domain, _, account = head.partition("/")
            cache.append(
                MSCacheEntry(
                    account=account,
                    dcc2_hash=hash_part,
                    domain=domain,
                )
            )
        elif section == "lsa":
            # Indented LSA pairs look like "  $MACHINE.ACC: 0x0102..." or
            # "  NL$KM:0102..." depending on the impacket version. Lines
            # without a colon are section sub-banners we already skipped
            # via the [*] check; treat anything else as a name:hex pair.
            name, sep, value = stripped.partition(":")
            if not sep:
                continue
            lsa.append(
                LSASecret(
                    name=name.strip(),
                    value_hex=value.strip(),
                )
            )

    if non_banner_lines > 0 and not (ntlm or lsa or cache):
        warnings.append(
            "secretsdump produced output but no SAM/LSA/MSCache rows could be parsed"
        )
    return ntlm, lsa, cache, warnings


async def secretsdump_local(
    sam: Path,
    security: Path,
    system: Path,
    timeout_s: int = 300,
) -> CredentialDumpReport:
    """Run ``impacket-secretsdump.py LOCAL`` against a hive triple.

    Args:
        sam: Path to the SAM hive.
        security: Path to the SECURITY hive.
        system: Path to the SYSTEM hive (needed for bootkey / SYSKEY).
        timeout_s: Subprocess timeout in seconds.

    Returns:
        :class:`CredentialDumpReport` with parsed rows. When the
        subprocess completes but produces no parseable output the
        report's ``parse_warnings`` list will explain why and the row
        lists will be empty.

    Raises:
        FileNotFoundError: A hive path doesn't exist on disk.
        PermissionError: A hive path violates Thymus policy.
        RuntimeError: ``impacket-secretsdump.py`` isn't on PATH (raised
            with the install hint).
        TimeoutError: subprocess exceeded ``timeout_s``.
    """
    sam_p = Path(sam)
    sec_p = Path(security)
    sys_p = Path(system)

    for hive_path, label in (
        (sam_p, "SAM"),
        (sec_p, "SECURITY"),
        (sys_p, "SYSTEM"),
    ):
        if not hive_path.exists():
            raise FileNotFoundError(f"{label} hive not found: {hive_path}")
        _check_thymus(hive_path, label)

    tool = _resolve_tool()
    if not tool:
        raise RuntimeError(INSTALL_HINT)

    cmd = [
        tool,
        "-system", str(sys_p),
        "-sam", str(sam_p),
        "-security", str(sec_p),
        "LOCAL",
    ]
    logger.info("Running: %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    import contextlib

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=timeout_s
        )
    except TimeoutError as exc:
        proc.kill()
        with contextlib.suppress(TimeoutError, ProcessLookupError):
            await asyncio.wait_for(proc.wait(), timeout=2.0)
        raise TimeoutError(
            f"impacket-secretsdump timed out after {timeout_s}s"
        ) from exc

    stdout = stdout_bytes.decode(errors="replace")
    stderr = stderr_bytes.decode(errors="replace")
    rc = proc.returncode if proc.returncode is not None else -1

    ntlm, lsa, cache, warnings = _parse_secretsdump_output(stdout)

    if rc != 0 and not (ntlm or lsa or cache):
        warnings.append(
            f"secretsdump exited rc={rc}; stderr head: {stderr[:300]}"
        )

    return CredentialDumpReport(
        sam_hive=str(sam_p),
        security_hive=str(sec_p),
        system_hive=str(sys_p),
        tool_path=tool,
        return_code=rc,
        ntlm_hashes=ntlm,
        lsa_secrets=lsa,
        cached_domain_creds=cache,
        parse_warnings=warnings,
        raw_stderr=stderr[:1000],
    )


__all__ = [
    "CredentialDumpReport",
    "INSTALL_HINT",
    "LSASecret",
    "MSCacheEntry",
    "NTLMHashRow",
    "secretsdump_local",
]
