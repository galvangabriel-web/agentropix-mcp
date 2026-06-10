"""WazuhConfig — typed configuration reader for the Wazuh integration.

Mirrors the precedence pattern from ``agentropix_mcp.secrets`` and the
variable table in ``01_design.md`` §12. Every variable is read once at
construction time; no global state is mutated. Tests build WazuhConfig
instances directly without touching os.environ by passing an explicit
``env`` mapping.

Security fix S-4 (01_security.md): ``WAZUH_TLS_VERIFY=false`` is only
permitted when ``AGENTROPIX_ENV=development``; any other environment
raises ConfigError immediately.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

__all__ = ["WazuhConfig", "ConfigError", "MisconfigurationError"]


class ConfigError(Exception):
    """Raised when a WazuhConfig invariant is violated at construction."""


# Alias so the error tree matches the design doc.
MisconfigurationError = ConfigError


def _bool_env(key: str, default: bool, env: dict[str, str]) -> bool:
    raw = env.get(key, "").strip().lower()
    if not raw:
        return default
    if raw in ("true", "1", "yes"):
        return True
    if raw in ("false", "0", "no"):
        return False
    raise ConfigError(f"{key} must be 'true' or 'false', got {raw!r}")


def _int_env(key: str, default: int, env: dict[str, str], lo: int, hi: int) -> int:
    raw = env.get(key, "").strip()
    if not raw:
        return default
    try:
        v = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{key} must be an integer, got {raw!r}") from exc
    if not (lo <= v <= hi):
        raise ConfigError(f"{key}={v} out of range [{lo}, {hi}]")
    return v


def _float_env(key: str, default: float, env: dict[str, str], lo: float, hi: float) -> float:
    raw = env.get(key, "").strip()
    if not raw:
        return default
    try:
        v = float(raw)
    except ValueError as exc:
        raise ConfigError(f"{key} must be a float, got {raw!r}") from exc
    if not (lo <= v <= hi):
        raise ConfigError(f"{key}={v} out of range [{lo}, {hi}]")
    return v


def _read_token_file(path: str, *, require_safe_perms: bool = True) -> str | None:
    """Return the first non-empty line of path, or None on error.

    F-5: when ``require_safe_perms`` is True (default), raises
    ``ConfigError`` if the file is group/world-readable (mode bits other
    than the owner's). ADR-020 Rule 1 mandates 0600 (or stricter) on
    cred files.
    """
    if require_safe_perms:
        try:
            st = os.stat(path)
        except OSError:
            return None
        # Refuse if any group/world bits are set on the file. Symlinks
        # are followed by os.stat; that's intentional — the resolved
        # file's perms are what matter.
        if st.st_mode & 0o077:
            raise ConfigError(
                f"Wazuh credential file {path!r} has unsafe permissions "
                f"(mode={oct(st.st_mode & 0o777)}); chmod 600 required "
                "(ADR-020 Rule 1)"
            )
    try:
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()
    except OSError:
        return None
    token = raw.strip()
    return token or None


class WazuhConfig:
    """Typed, immutable configuration for the Wazuh integration.

    All fields are validated at construction. No field can be mutated
    after construction — the object is effectively frozen.

    Correct ADRs: ADR-008 (safety), ADR-016 (courtroom seal), ADR-017 (tailnet).
    """

    # ------------------------------------------------------------------ #
    # Kill switches                                                        #
    # ------------------------------------------------------------------ #
    integration_enabled: bool
    push_enabled: bool
    dry_run_only: bool

    # ------------------------------------------------------------------ #
    # Connectivity                                                         #
    # ------------------------------------------------------------------ #
    manager_url: str  # required; https scheme; RFC1918/CGNAT or allow_public_endpoint
    indexer_url: str | None  # optional; Step 2
    # WZ-002: Indexer Basic Auth credentials. Optional at the config layer
    # so the orchestrator (which only needs the Manager API) loads cleanly
    # without them. IndexerClient construction raises if these are unset
    # when callers actually need indexer access.
    indexer_user: str | None
    indexer_password: str | None

    # ------------------------------------------------------------------ #
    # Authentication                                                       #
    # ------------------------------------------------------------------ #
    api_user: str  # required
    api_password: str  # resolved; never None after from_env()

    # ------------------------------------------------------------------ #
    # TLS                                                                  #
    # ------------------------------------------------------------------ #
    tls_verify: bool  # default True; False only in development
    tls_ca_bundle: str  # default /etc/ssl/certs/ca-certificates.crt
    # W-181: independent indexer TLS toggle. The Wazuh Indexer ships
    # with a self-signed CA distinct from the manager bundle; during
    # transition the manager can be verify=True while the indexer is
    # verify=False without weakening manager-side TLS. Defaults to
    # tls_verify when WAZUH_INDEXER_TLS_VERIFY is unset (back-compat).
    indexer_tls_verify: bool

    # ------------------------------------------------------------------ #
    # Rate limiting & timeouts                                             #
    # ------------------------------------------------------------------ #
    write_rate_per_sec: float  # default 5; range (0, 50]
    restart_timeout_sec: int  # default 90; range [30, 600]
    jwt_refresh_at_sec: int  # default 890; range [60, 899]

    # ------------------------------------------------------------------ #
    # Paths                                                                #
    # ------------------------------------------------------------------ #
    audit_log: str  # default /var/log/agentropix/wazuh-audit.jsonl
    dlq_dir: str  # default /var/lib/agentropix/wazuh-dlq

    # ------------------------------------------------------------------ #
    # Namespace / rule-id                                                  #
    # ------------------------------------------------------------------ #
    list_namespace: str  # default agentropix_
    ip_allowlist: list[str]  # CIDR strings; never pushed as IOC

    def __init__(  # noqa: PLR0913 — config object intentionally has many fields
        self,
        *,
        integration_enabled: bool = False,
        push_enabled: bool = False,
        dry_run_only: bool = True,
        manager_url: str,
        indexer_url: str | None = None,
        indexer_user: str | None = None,
        indexer_password: str | None = None,
        api_user: str,
        api_password: str,
        tls_verify: bool = True,
        tls_ca_bundle: str = "/etc/ssl/certs/ca-certificates.crt",
        indexer_tls_verify: bool | None = None,
        write_rate_per_sec: float = 5.0,
        restart_timeout_sec: int = 90,
        jwt_refresh_at_sec: int = 890,
        audit_log: str = "/var/log/agentropix/wazuh-audit.jsonl",
        dlq_dir: str = "/var/lib/agentropix/wazuh-dlq",
        list_namespace: str = "agentropix_",
        ip_allowlist: list[str] | None = None,
    ) -> None:
        self.integration_enabled = integration_enabled
        self.push_enabled = push_enabled
        self.dry_run_only = dry_run_only
        self.manager_url = manager_url
        self.indexer_url = indexer_url
        self.indexer_user = indexer_user
        self.indexer_password = indexer_password
        self.api_user = api_user
        self.api_password = api_password
        self.tls_verify = tls_verify
        self.tls_ca_bundle = tls_ca_bundle
        self.indexer_tls_verify = (
            tls_verify if indexer_tls_verify is None else indexer_tls_verify
        )
        self.write_rate_per_sec = write_rate_per_sec
        self.restart_timeout_sec = restart_timeout_sec
        self.jwt_refresh_at_sec = jwt_refresh_at_sec
        self.audit_log = audit_log
        self.dlq_dir = dlq_dir
        self.list_namespace = list_namespace
        self.ip_allowlist = ip_allowlist or ["127.0.0.1", "::1"]

    # F-5 (review): redacted repr/str so the password never lands in
    # logs, tracebacks, or sentry frames. ADR-020 Rule 5.
    def __repr__(self) -> str:
        masked = "***REDACTED***" if self.api_password else "<empty>"
        return (
            f"WazuhConfig(manager_url={self.manager_url!r}, "
            f"api_user={self.api_user!r}, api_password={masked}, "
            f"tls_verify={self.tls_verify}, audit_log={self.audit_log!r})"
        )

    __str__ = __repr__

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> WazuhConfig:
        """Build a WazuhConfig from environment variables.

        Fix S-4: if WAZUH_TLS_VERIFY=false and AGENTROPIX_ENV != 'development',
        raises ConfigError immediately — TLS verification cannot be disabled
        outside the development environment.
        """
        e = env if env is not None else dict(os.environ)

        # --- kill switches ---
        integration_enabled = _bool_env("WAZUH_INTEGRATION_ENABLED", False, e)
        push_enabled = _bool_env("WAZUH_PUSH_ENABLED", False, e)
        dry_run_only = _bool_env("WAZUH_DRY_RUN_ONLY", True, e)

        # --- connectivity ---
        manager_url = e.get("WAZUH_MANAGER_URL", "").strip()
        if not manager_url:
            raise MisconfigurationError("WAZUH_MANAGER_URL is required; see .env.example")
        if not manager_url.startswith("https://"):
            raise ConfigError("WAZUH_MANAGER_URL must use https scheme (ADR-017 tailnet enforcement)")
        indexer_url = e.get("WAZUH_INDEXER_URL", "").strip() or None
        # WZ-002: Indexer Basic Auth via env. Empty/missing -> None so
        # IndexerClient construction can detect "not configured" and
        # raise a clear error at the call site rather than silently
        # sending unauthenticated requests.
        indexer_user = e.get("WAZUH_INDEXER_USER", "").strip() or None
        indexer_password = e.get("WAZUH_INDEXER_PASS", "").strip() or None

        # --- authentication ---
        api_user = e.get("AGENTROPIX_WAZUH_API_USER", "").strip()
        if not api_user:
            raise MisconfigurationError("AGENTROPIX_WAZUH_API_USER is required; see .env.example")
        api_password = _load_wazuh_password(e)

        # --- TLS (Fix S-4) ---
        tls_verify = _bool_env("WAZUH_TLS_VERIFY", True, e)
        if not tls_verify:
            agentropix_env = e.get("AGENTROPIX_ENV", "production").strip().lower()
            if agentropix_env != "development":
                raise ConfigError(
                    "WAZUH_TLS_VERIFY=false is only permitted when "
                    "AGENTROPIX_ENV=development (security fix S-4). "
                    "Set AGENTROPIX_ENV=development in your .env to override "
                    "(never in production)."
                )
        tls_ca_bundle = e.get("WAZUH_TLS_CA_BUNDLE", "/etc/ssl/certs/ca-certificates.crt").strip()

        # W-181: independent indexer TLS toggle. If unset, falls back to
        # tls_verify (back-compat). If set, must parse to a bool.
        #
        # W-181-FIX (C3-F1): the S-4 production gate (ADR-018 Decision 3)
        # applies symmetrically to the indexer path. Setting
        # WAZUH_INDEXER_TLS_VERIFY=false outside development re-opens the
        # exact MITM surface S-4 closed (every hunt query, IOC verification
        # read, and future indexer write goes over an unverified TLS link).
        # Reject with the same gate as WAZUH_TLS_VERIFY=false.
        indexer_tls_verify: bool | None
        if e.get("WAZUH_INDEXER_TLS_VERIFY", "").strip():
            indexer_tls_verify = _bool_env("WAZUH_INDEXER_TLS_VERIFY", tls_verify, e)
            if not indexer_tls_verify:
                agentropix_env = e.get("AGENTROPIX_ENV", "production").strip().lower()
                if agentropix_env != "development":
                    raise ConfigError(
                        "WAZUH_INDEXER_TLS_VERIFY=false is only permitted when "
                        "AGENTROPIX_ENV=development (ADR-018 Decision 3, S-4 gate). "
                        "Set AGENTROPIX_ENV=development in your .env to override "
                        "(never in production)."
                    )
        else:
            indexer_tls_verify = None

        # --- rate limiting & timeouts ---
        write_rate_per_sec = _float_env("WAZUH_WRITE_RATE_PER_SEC", 5.0, e, 0.01, 50.0)
        restart_timeout_sec = _int_env("WAZUH_RESTART_TIMEOUT_SEC", 90, e, 30, 600)
        jwt_refresh_at_sec = _int_env("WAZUH_JWT_REFRESH_AT_SEC", 890, e, 60, 899)

        # --- paths ---
        audit_log = e.get("WAZUH_AUDIT_LOG", "/var/log/agentropix/wazuh-audit.jsonl").strip()
        dlq_dir = e.get("WAZUH_DLQ_DIR", "/var/lib/agentropix/wazuh-dlq").strip()

        # --- namespace ---
        list_namespace = e.get("WAZUH_LIST_NAMESPACE", "agentropix_").strip()

        # --- IP allowlist ---
        raw_allowlist = e.get("WAZUH_IP_ALLOWLIST", "127.0.0.1,::1").strip()
        ip_allowlist = [s.strip() for s in raw_allowlist.split(",") if s.strip()]

        return cls(
            integration_enabled=integration_enabled,
            push_enabled=push_enabled,
            dry_run_only=dry_run_only,
            manager_url=manager_url,
            indexer_url=indexer_url,
            indexer_user=indexer_user,
            indexer_password=indexer_password,
            api_user=api_user,
            api_password=api_password,
            tls_verify=tls_verify,
            tls_ca_bundle=tls_ca_bundle,
            indexer_tls_verify=indexer_tls_verify,
            write_rate_per_sec=write_rate_per_sec,
            restart_timeout_sec=restart_timeout_sec,
            jwt_refresh_at_sec=jwt_refresh_at_sec,
            audit_log=audit_log,
            dlq_dir=dlq_dir,
            list_namespace=list_namespace,
            ip_allowlist=ip_allowlist,
        )


def _load_wazuh_password(env: dict[str, str]) -> str:
    """Resolve the Wazuh API password via the precedence chain.

    1. AGENTROPIX_WAZUH_API_PASSWORD_FILE — path to file (preferred)
    2. AGENTROPIX_WAZUH_API_PASSWORD — inline value (fallback)
    """
    file_path = env.get("AGENTROPIX_WAZUH_API_PASSWORD_FILE", "").strip()
    if file_path:
        token = _read_token_file(file_path)
        if token:
            return token

    inline = env.get("AGENTROPIX_WAZUH_API_PASSWORD", "").strip()
    if inline:
        return inline

    raise MisconfigurationError(
        "Wazuh API password not set; set AGENTROPIX_WAZUH_API_PASSWORD_FILE "
        "or AGENTROPIX_WAZUH_API_PASSWORD in .env (see .env.example)"
    )
