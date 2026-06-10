"""WazuhClient — the sole owner of the httpx.AsyncClient for Wazuh API calls.

Fix 1 (CRITICAL S-1): ``_request`` MUST call thymus_bridge.validate_input()
AND evidence_gate.verify_evidence_token() before any PUT/POST to Wazuh.
This is enforced at the ``_request`` level so no code path can bypass it.

Fix 3 (S-4): TLS verification is already enforced at the config layer;
this module never creates a client with tls_verify=False unless the config
explicitly permits it (development only).

Correct ADRs: ADR-008 (safety/Thymus), ADR-016 (courtroom seal), ADR-017 (tailnet).
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime
from typing import Any

__all__ = [
    "WazuhClient",
    "WazuhError",
    "AuthError",
    "RateLimitedError",
    "PayloadTooLargeError",
    "RuleValidationError",
    "RestartTimeoutError",
    "NamespaceViolation",
    "TLSFailure",
    "IOCRemovalRequiresConfirmation",
]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Error hierarchy
# ---------------------------------------------------------------------------


class WazuhError(Exception):
    """Base class for all Wazuh integration errors."""


class AuthError(WazuhError):
    """JWT authentication failed after one refresh attempt."""


class RateLimitedError(WazuhError):
    """Wazuh returned 429; retry_after_sec is the suggested wait."""

    def __init__(self, msg: str, retry_after_sec: float = 1.0) -> None:
        super().__init__(msg)
        self.retry_after_sec = retry_after_sec


class PayloadTooLargeError(WazuhError):
    """PUT body exceeds Wazuh max_upload_size (413)."""


class RuleValidationError(WazuhError):
    """Wazuh rejected the rules XML (400)."""

    def __init__(self, msg: str, server_reason: str = "") -> None:
        super().__init__(msg)
        self.server_reason = server_reason


class RestartTimeoutError(WazuhError):
    """Manager restart polling exceeded WAZUH_RESTART_TIMEOUT_SEC."""


class NamespaceViolation(WazuhError):
    """Attempted to write to a list name outside the agentropix_* namespace."""


class TLSFailure(WazuhError):
    """TLS certificate verification or connection error."""


class IOCRemovalRequiresConfirmation(WazuhError):
    """Re-publish would silently REMOVE keys from an existing CDB list.

    Plan §5.3 / review F-3: a `PUT /lists/files/<name>` is full-file replace
    on the manager side. If the new payload is missing keys that the
    existing list contains, the result is silent IOC removal. This error
    is raised by the orchestrator's pre-PUT diff guard when removed_keys
    is non-empty and the caller did not pass `confirm_remove=True`.
    """

    def __init__(self, list_name: str, removed_keys: tuple[str, ...]) -> None:
        self.list_name = list_name
        self.removed_keys = removed_keys
        sample = ", ".join(removed_keys[:5]) + ("…" if len(removed_keys) > 5 else "")
        super().__init__(
            f"Re-publish to {list_name!r} would REMOVE {len(removed_keys)} key(s) "
            f"({sample}); pass confirm_remove=True to proceed"
        )


# ---------------------------------------------------------------------------
# CDB namespace enforcer
# ---------------------------------------------------------------------------

class _TokenBucket:
    """W-A05: simple async token-bucket for write-rate pacing.

    Refills at ``rate_per_sec`` tokens per second up to ``capacity``. Each
    PUT acquires one token; if the bucket is empty, ``acquire()`` sleeps
    until enough time has passed for the next token. Enforces the
    ``WAZUH_WRITE_RATE_PER_SEC`` config value at the wire layer.
    """

    def __init__(self, rate_per_sec: float, capacity: int) -> None:
        self._rate = max(0.01, float(rate_per_sec))
        self._capacity = max(1, int(capacity))
        self._tokens = float(self._capacity)
        self._last_refill = time.monotonic()
        self._lock: asyncio.Lock | None = None

    async def acquire(self) -> None:
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._last_refill
                self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
                self._last_refill = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                # Need to wait for the next token to refill.
                wait = (1.0 - self._tokens) / self._rate
                await asyncio.sleep(wait)


_ALLOWED_LIST_NAMES = frozenset(
    {
        "agentropix_c2_ips",
        "agentropix_malware_sha256",
        "agentropix_malware_md5",
        "agentropix_suspect_process",  # legacy / deprecated (Issue #60)
        "agentropix_suspect_image",  # Issue #60: Sysmon EID 1
        "agentropix_suspect_module",  # Issue #60: Sysmon EID 7
        "agentropix_persistence_regkey",
    }
)

_ALLOWED_RULES_FILES = frozenset({"agentropix_srl2018_rules.xml"})


def _enforce_namespace(name: str) -> None:
    """Raise NamespaceViolation if name is outside the agentropix_* namespace."""
    if not name.startswith("agentropix_"):
        raise NamespaceViolation(
            f"List/rules name {name!r} is outside the agentropix_* namespace. "
            "Step 1 only writes agentropix_* resources."
        )


# ---------------------------------------------------------------------------
# WazuhClient
# ---------------------------------------------------------------------------


class WazuhClient:
    """Async Wazuh Manager API client.

    The ONLY class that ever opens an HTTP connection to the Wazuh manager.
    No DELETE methods are implemented (Step 1 is additive-only).

    Fix 1 (S-1): ``_request`` calls thymus_bridge AND evidence_gate before
    every write (PUT/POST). This cannot be bypassed because all public write
    methods route through ``_request``.

    Args:
        config: WazuhConfig instance.
        thymus: ThymusBridge instance (injectable for testing).
        evidence_gate: EvidenceGate instance (injectable for testing).
        session_key: 32-byte HMAC key for this push run.
        evidence_token: The operator's mutation token (verified once).
        operator: UNIX username holding the token.
        case_id: Case ID for audit trail.
    """

    def __init__(
        self,
        config: Any,  # WazuhConfig; Any to avoid circular at module level
        *,
        thymus: Any | None = None,
        evidence_gate: Any | None = None,
        session_key: bytes | None = None,
        evidence_token: str | None = None,
        operator: str = "agentropix-mcp",
        case_id: str = "UNKNOWN",
        run_id: str = "",
    ) -> None:
        self._config = config
        self._session_key = session_key or b""
        self._evidence_token = evidence_token
        self._operator = operator
        self._case_id = case_id
        # W-A17: run_id needed for sealed jwt.refresh audit rows from inside _request.
        self._run_id = run_id
        self._jwt: str | None = None
        self._jwt_issued_at: datetime | None = None
        # W-A06: asyncio.Lock guards concurrent JWT mint/refresh.
        self._jwt_lock: asyncio.Lock | None = None

        # Dependency injection (defaults to module singletons)
        if thymus is None:
            from agentropix_mcp.wazuh.thymus_bridge import ThymusBridge

            thymus = ThymusBridge()
        if evidence_gate is None:
            from agentropix_mcp.wazuh.evidence_gate import EvidenceGate

            evidence_gate = EvidenceGate()

        self._thymus = thymus
        self._evidence_gate = evidence_gate
        # F-11: single shared AsyncClient memoised on the instance so we
        # reuse the TLS connection across PUTs in the same push run.
        self._http_client: Any | None = None

        # W-A05: token-bucket pacing for write-rate limiting.
        rate = float(getattr(config, "write_rate_per_sec", 5.0))
        self._rate_limiter = _TokenBucket(rate_per_sec=rate, capacity=max(1, int(rate)))

    def _emit_jwt_refresh_seal(self, *, path: str, latency_ms: float, evidence_token: str | None) -> None:
        """W-A17: emit a sealed audit row for a JWT-refresh attempt.

        Builds a CourtroomSeal under the per-run session_key and writes a
        degenerate envelope (req=resp=b"") that binds endpoint, run_id,
        operator. Best-effort — never raises; if the seal helper or audit
        log fails the refresh path still proceeds. The seal asymmetry this
        closes was flagged by critic-courtroom (per-attempt visibility gap
        in the 401 single-refresh recursion).
        """
        if not self._session_key:
            return  # No session key available — sealing not configured.
        try:
            from agentropix_mcp.wazuh.orchestrator import _seal_and_audit_attempt
            from agentropix_mcp.wazuh.seal import CourtroomSeal

            seal_helper = CourtroomSeal(self._session_key)
            audit_log = getattr(self._config, "audit_log", None)
            if audit_log is None:
                return
            _seal_and_audit_attempt(
                audit_log=audit_log,
                seal_helper=seal_helper,
                operator=self._operator,
                case_id=self._case_id,
                run_id=self._run_id or "unknown",
                event="wazuh.jwt.refresh",
                op="jwt.refresh",
                endpoint=path,
                evidence_token=evidence_token or self._evidence_token,
                req_body=b"",
                resp_body=b"",
                status=401,
                latency_ms=latency_ms,
                result="refresh_attempted",
                error_class="HTTP401",
            )
        except Exception as exc:  # noqa: BLE001
            # F-2 / F-11 pattern: telemetry must never block the recovery path.
            logger.warning("jwt.refresh seal emission failed: %s", exc)

    @staticmethod
    async def _redact_request_log(request: Any) -> None:
        """F-8 httpx event hook: scrub Authorization before logging.

        Hook is attached to ``event_hooks={"request": [...]}``; httpx
        invokes it before the wire send. We mutate a shadow header for
        the local logger only — the real request still carries the
        Authorization header to Wazuh.
        """
        # Best-effort: attach a redacted snapshot for downstream log
        # filters; never raise back into the request path.
        import contextlib

        with contextlib.suppress(Exception):
            request.extensions["redacted_authorization"] = "Bearer ***REDACTED***"

    async def _get_http_client(self):  # type: ignore[return]
        """F-11: return a single shared AsyncClient for this push run."""
        if self._http_client is not None:
            return self._http_client

        try:
            import httpx
        except ImportError as exc:  # pragma: no cover
            raise WazuhError("httpx is not installed; install with: uv add httpx>=0.27") from exc

        verify: bool | str = self._config.tls_verify
        if verify and self._config.tls_ca_bundle:
            import os

            if os.path.isfile(self._config.tls_ca_bundle):
                verify = self._config.tls_ca_bundle

        self._http_client = httpx.AsyncClient(
            base_url=self._config.manager_url,
            verify=verify,
            timeout=30.0,
            event_hooks={"request": [self._redact_request_log]},
        )
        return self._http_client

    async def aclose(self) -> None:
        """F-11: close the shared AsyncClient (idempotent)."""
        if self._http_client is not None:
            try:
                await self._http_client.aclose()
            except Exception as exc:  # noqa: BLE001
                logger.warning("AsyncClient close failed: %s", exc)
            self._http_client = None

    async def __aenter__(self) -> WazuhClient:
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.aclose()

    async def _ensure_jwt(self) -> str:
        """Return a valid JWT, minting or refreshing as needed.

        W-A06: protected by ``self._jwt_lock`` so two concurrent callers
        with a stale JWT do not both POST ``/security/user/authenticate``.
        """
        # Lazy-init the lock so __init__ doesn't need a running loop.
        if self._jwt_lock is None:
            self._jwt_lock = asyncio.Lock()

        async with self._jwt_lock:
            now = datetime.now(UTC)
            refresh_at_sec = getattr(self._config, "jwt_refresh_at_sec", 890)

            if self._jwt is not None and self._jwt_issued_at is not None:
                age = (now - self._jwt_issued_at).total_seconds()
                if age < refresh_at_sec:
                    return self._jwt

            # Mint a new JWT
            try:
                import httpx
            except ImportError as exc:  # pragma: no cover
                raise WazuhError("httpx not installed") from exc

            try:
                import base64

                credentials = base64.b64encode(
                    f"{self._config.api_user}:{self._config.api_password}".encode()
                ).decode()
                client = await self._get_http_client()
                # F-11: do not `async with` — share the connection pool.
                resp = await client.post(
                    "/security/user/authenticate?raw=true",
                    headers={"Authorization": f"Basic {credentials}"},
                )
            except httpx.ConnectError as exc:
                raise TLSFailure(f"Cannot connect to Wazuh manager: {exc}") from exc
            except httpx.ConnectTimeout as exc:
                raise TLSFailure(f"Connection timeout to Wazuh manager: {exc}") from exc

            if resp.status_code == 401:
                raise AuthError("Wazuh authentication failed (401); check credentials")
            if resp.status_code != 200:
                raise WazuhError(f"JWT mint failed with status {resp.status_code}")

            self._jwt = resp.text.strip()
            self._jwt_issued_at = now
            logger.info("Wazuh JWT minted (age=0s)")
            return self._jwt

    async def _request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        content_type: str = "application/octet-stream",
        evidence_token: str | None = None,
        _refresh_count: int = 0,
        _rate_retry_count: int = 0,
    ) -> tuple[int, bytes, float]:
        """Execute a single HTTP request to the Wazuh manager.

        CRITICAL (Fix 1 / S-1): Before any write (PUT/POST), this method:
        1. Calls thymus_bridge.validate_input() on the path
        2. Calls evidence_gate.verify_evidence_token() to confirm the
           operator has authorised this mutation

        These calls are here at the ``_request`` level so they CANNOT be
        bypassed by any calling code.

        W-A05: writes are paced through a token bucket; on 429, the call
        sleeps `Retry-After` and retries up to 3 times.
        W-A06: ``_refresh_count`` and ``_rate_retry_count`` are per-call
        recursion counters, not instance state, so concurrent failures
        cannot starve each other.

        Returns:
            (status_code, response_body_bytes, latency_ms)
        """
        # Fix 1 (S-1): Thymus STRICT on every write path
        if method in ("PUT", "POST"):
            self._thymus.validate_input(path, field_name="endpoint")
            if body:
                # Validate a representative sample of the body (T2 touchpoint).
                # Uses validate_body_sample (not validate_input) because CDB
                # plaintext format legitimately contains newline+colon on every
                # line; the colon-injection guard is IOC-value-level only.
                sample = body[:1024].decode("utf-8", errors="replace")
                self._thymus.validate_body_sample(sample, field_name="request_body_sample")

            # Fix 1 (S-1): EvidenceGate on every write path
            token = evidence_token or self._evidence_token
            self._evidence_gate.check(token, op="push_iocs")

            # W-A05: pace writes via the configured token bucket.
            await self._rate_limiter.acquire()

        try:
            import httpx
        except ImportError as exc:  # pragma: no cover
            raise WazuhError("httpx not installed") from exc

        jwt = await self._ensure_jwt()
        headers = {
            "Authorization": f"Bearer {jwt}",
            "Content-Type": content_type,
        }

        t0 = time.monotonic()
        try:
            # F-11: do NOT `async with` the client here — that closes the
            # connection pool every call. The shared client is opened
            # once via _get_http_client and closed via aclose / __aexit__.
            client = await self._get_http_client()
            if method == "PUT":
                resp = await client.put(path, content=body or b"", headers=headers)
            elif method == "POST":
                resp = await client.post(path, content=body or b"", headers=headers)
            elif method == "GET":
                resp = await client.get(path, headers={"Authorization": f"Bearer {jwt}"})
            else:
                raise WazuhError(f"Unsupported HTTP method: {method}")
        except httpx.ConnectError as exc:
            raise TLSFailure(str(exc)) from exc
        except httpx.ConnectTimeout as exc:
            raise TLSFailure(str(exc)) from exc

        latency_ms = (time.monotonic() - t0) * 1000.0

        # Handle 401 — single refresh (W-A06: per-call counter, not instance)
        if resp.status_code == 401 and _refresh_count == 0:
            logger.warning("Wazuh 401: refreshing JWT (attempt 1/1)")
            # W-A17: seal the first-401 attempt so the JWT-refresh window
            # is provably attributable. Closes the per-attempt visibility
            # gap critic-courtroom flagged. Best-effort — never blocks
            # the recovery path.
            self._emit_jwt_refresh_seal(path=path, latency_ms=latency_ms, evidence_token=evidence_token)
            self._jwt = None
            return await self._request(
                method,
                path,
                body=body,
                content_type=content_type,
                evidence_token=evidence_token,
                _refresh_count=1,
                _rate_retry_count=_rate_retry_count,
            )

        if resp.status_code == 401:
            raise AuthError("Wazuh 401 after JWT refresh; check credentials and RBAC scope")

        # W-A05: 429 retry loop with Retry-After honoured (max 3 attempts).
        if resp.status_code == 429:
            retry_after = float(resp.headers.get("Retry-After", "1"))
            if _rate_retry_count < 3:
                logger.warning(
                    "Wazuh 429 on %s; sleeping %.1fs and retrying (%d/3)",
                    path, retry_after, _rate_retry_count + 1,
                )
                await asyncio.sleep(retry_after)
                return await self._request(
                    method,
                    path,
                    body=body,
                    content_type=content_type,
                    evidence_token=evidence_token,
                    _refresh_count=_refresh_count,
                    _rate_retry_count=_rate_retry_count + 1,
                )
            raise RateLimitedError(
                f"Wazuh 429 on {path} after 3 retries; Retry-After={retry_after}s",
                retry_after_sec=retry_after,
            )

        if resp.status_code == 413:
            raise PayloadTooLargeError(f"Wazuh 413: payload for {path} exceeds max_upload_size")

        if resp.status_code == 400 and "rules/files" in path:
            # F-8: do NOT echo raw response body into the exception
            # message. Wazuh 400 typically echoes the offending XML
            # stanza, which contains attacker-controllable content from
            # the rules pack. We hash the body for correlation and
            # capture only the response length as a structured signal.
            import hashlib as _hashlib

            body_digest = _hashlib.sha256(resp.content).hexdigest()[:16]
            raise RuleValidationError(
                f"Wazuh 400: rules XML rejected for {path}",
                server_reason=f"resp_digest={body_digest} resp_len={len(resp.content)}",
            )

        return resp.status_code, resp.content, latency_ms

    async def put_cdb_list(
        self,
        name: str,
        body: bytes,
        *,
        evidence_token: str | None = None,
    ) -> tuple[int, bytes, float]:
        """PUT a CDB list payload to Wazuh.

        Enforces the agentropix_* namespace; raises NamespaceViolation otherwise.
        """
        _enforce_namespace(name)
        # overwrite=true is required to update an existing CDB list file;
        # without it Wazuh returns HTTP 200 with total_failed_items=1 and
        # silently leaves the file unchanged (Wazuh API error 1905).
        path = f"/lists/files/{name}?overwrite=true"
        return await self._request(
            "PUT",
            path,
            body=body,
            content_type="application/octet-stream",
            evidence_token=evidence_token,
        )

    async def put_rules_xml(
        self,
        name: str,
        body: bytes,
        *,
        evidence_token: str | None = None,
    ) -> tuple[int, bytes, float]:
        """PUT a custom rules XML file to Wazuh."""
        _enforce_namespace(name)
        path = f"/rules/files/{name}"
        return await self._request(
            "PUT",
            path,
            body=body,
            content_type="application/octet-stream",
            evidence_token=evidence_token,
        )

    async def restart_manager(
        self,
        *,
        evidence_token: str | None = None,
    ) -> tuple[int, bytes, float]:
        """Trigger one coalesced manager restart (FR-7)."""
        return await self._request(
            "PUT",
            "/manager/restart",
            body=b"",
            content_type="application/json",
            evidence_token=evidence_token,
        )

    async def run_logtest(
        self,
        event: str,
        *,
        log_format: str = "syslog",
        location: str = "agentropix-self-test",
        evidence_token: str | None = None,
    ) -> dict:
        """WLV-02: PUT /logtest with a sentinel event; return the parsed
        response payload.

        Wazuh's /logtest is the simulation-only validator (T-LIVE
        DEFECT-LIVE-02): it runs the event through decoders + rule
        engine without writing to alerts.json. Perfect for the
        post-restart self-test — proves the rule chain is wired without
        polluting the indexer.

        Args:
            event: the raw event string (or JSON-string for log_format=json).
            log_format: "syslog" / "json" / "syscheck" / etc. Must match
                the rule's <if_group> for the rule to fire.
            location: free-text location label that surfaces in the
                logtest response. Defaults to a SIFT-identifying value
                so manual log greps can isolate self-test traffic.
            evidence_token: passed through to the JWT mint chain.

        Returns:
            dict — the parsed JSON response. Empty dict on non-200 or
            JSON-parse failure (best-effort: caller MUST check
            ``data.output.alert`` rather than relying on raise-on-error).
        """
        import json as _json

        # /logtest expects a JSON envelope: {log_format, location, event}
        body_dict = {
            "log_format": log_format,
            "location": location,
            "event": event,
        }
        body = _json.dumps(body_dict, separators=(",", ":")).encode("utf-8")
        status, resp_body, _ = await self._request(
            "PUT",
            "/logtest",
            body=body,
            content_type="application/json",
            evidence_token=evidence_token,
        )
        if status != 200:
            return {}
        try:
            return dict(_json.loads(resp_body))
        except Exception:  # noqa: BLE001
            return {}

    async def get_cdb_list(self, name: str) -> bytes:
        """GET current CDB list contents (used by DryRunPlanner)."""
        path = f"/lists/files/{name}?raw=true"
        status, body, _ = await self._request("GET", path)
        if status == 404:
            return b""
        if status != 200:
            raise WazuhError(f"GET {path} returned {status}")
        return body

    async def get_rules_file(self, name: str) -> bytes:
        """GET current rules XML file (used by DryRunPlanner)."""
        path = f"/rules/files/{name}?raw=true"
        status, body, _ = await self._request("GET", path)
        if status == 404:
            return b""
        if status != 200:
            raise WazuhError(f"GET {path} returned {status}")
        return body

    async def get_manager_configuration(self) -> bytes:
        """GET the manager's current ossec.conf as XML bytes.

        WLV-01: needed by the orchestrator's pre-restart reconciler to
        ensure every CDB namespace this run wrote to is declared in
        <ruleset>. Without the declaration, wazuh-analysisd emits
        warning 7616 at restart and silently drops the rules that
        reference the missing list.
        """
        path = "/manager/configuration?raw=true"
        status, body, _ = await self._request("GET", path)
        # WLV-01d.1 (issue #52): a 404 on /manager/configuration is
        # never expected on a healthy 4.x cluster. Returning empty
        # bytes silently masked auth-path bugs and Wazuh-version skew.
        # Now we raise with the status so the reconciler's audit row
        # carries the actual HTTP code instead of just "empty body".
        if status != 200:
            hint = (
                "; manager API path missing or token unauthorised"
                if status in (401, 403, 404)
                else ""
            )
            raise WazuhError(f"GET {path} returned {status}{hint}")
        return body

    async def put_manager_configuration(
        self,
        body: bytes,
        *,
        evidence_token: str | None = None,
    ) -> tuple[int, bytes, float]:
        """PUT a patched ossec.conf back to the manager.

        WLV-01 companion to get_manager_configuration. Routes through
        ``_request`` so Thymus + EvidenceGate gating still runs on the
        write path (the patched XML carries operator-influenced bytes
        and must respect the same guarantees as a /rules/files PUT).
        """
        return await self._request(
            "PUT",
            "/manager/configuration",
            body=body,
            content_type="application/xml",
            evidence_token=evidence_token,
        )

    async def get_manager_status(self) -> dict:
        """GET manager status (used for restart polling)."""
        status, body, _ = await self._request("GET", "/manager/status")
        if status == 200:
            import json

            try:
                return dict(json.loads(body))
            except Exception:  # noqa: BLE001
                return {}
        return {}

    async def is_cluster_enabled(self) -> bool:
        """Return True iff the Wazuh deployment is in HA cluster mode.

        Queries ``GET /cluster/status`` which returns
        ``{"data": {"enabled": "yes"|"no", "running": "yes"|"no"}, ...}``.
        Treats anything other than ``enabled=yes AND running=yes`` as
        single-node (the safe default — single-node gating is a proper
        subset of cluster-aware gating).

        W-NEW-8 (2026-05-12): poll_restart promotes ``wazuh-clusterd``
        into the core required-daemons set only when this returns True.
        On single-node deployments ``wazuh-clusterd`` is intentionally
        stopped and excluded.

        Returns ``False`` on any HTTP error / malformed payload so a
        transient API hiccup never spuriously elevates the daemon set.
        """
        import json

        try:
            status, body, _ = await self._request("GET", "/cluster/status")
        except Exception:  # noqa: BLE001
            return False
        if status != 200:
            return False
        try:
            payload = json.loads(body)
        except Exception:  # noqa: BLE001
            return False
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, dict):
            return False
        enabled = str(data.get("enabled", "")).strip().lower()
        running = str(data.get("running", "")).strip().lower()
        return enabled == "yes" and running == "yes"

    async def get_cluster_node_names(self) -> list[str]:
        """Return cluster node names on HA deployments, else empty list.

        Queries ``GET /cluster/nodes``. On cluster-disabled hosts Wazuh
        returns HTTP 400 with ``error: 3013``; we map that to ``[]`` so
        callers can treat single-node and cluster paths uniformly.

        Used by W-NEW-8 per-node gating: poll_restart enumerates nodes,
        fetches each node's status, and requires every node to pass.
        """
        import json

        try:
            status, body, _ = await self._request("GET", "/cluster/nodes")
        except Exception:  # noqa: BLE001
            return []
        if status != 200:
            return []
        try:
            payload = json.loads(body)
        except Exception:  # noqa: BLE001
            return []
        data = payload.get("data") if isinstance(payload, dict) else None
        items = data.get("affected_items") if isinstance(data, dict) else None
        if not isinstance(items, list):
            return []
        names: list[str] = []
        for item in items:
            if isinstance(item, dict):
                name = item.get("name")
                if isinstance(name, str) and name:
                    names.append(name)
        return names

    async def get_cluster_node_status(self, node_name: str) -> dict:
        """GET cluster node status (per-node manager daemons).

        Wazuh 4.x path: ``/cluster/{node_name}/status``. Returns the same
        ``{"data": {"affected_items": [{daemon: state, ...}]}}`` shape
        as ``/manager/status``.

        Returns ``{}`` on any HTTP error / malformed payload.
        """
        from urllib.parse import quote

        path = f"/cluster/{quote(node_name, safe='')}/status"
        try:
            status, body, _ = await self._request("GET", path)
        except Exception:  # noqa: BLE001
            return {}
        if status != 200:
            return {}
        import json

        try:
            return dict(json.loads(body))
        except Exception:  # noqa: BLE001
            return {}

    async def get_manager_logs(
        self,
        *,
        level: str | None = None,
        tag: str | None = None,
        search: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """GET /manager/logs with optional filters; return affected_items.

        WLV-06: needed by the CDB-load health probe to surface warning
        code 7616 ("List 'etc/lists/<name>' could not be loaded. Rule
        '<id>' will be ignored.") within 30 s of any manager restart.

        Args:
            level: filter by log level ("info" / "warning" / "error").
            tag: filter by component tag (e.g. "wazuh-analysisd").
            search: substring match against description.
            limit: max number of items to return (Wazuh default 100,
                hard cap 500 in 4.x).

        Returns:
            list[dict] — each entry carries at least the keys
            ``timestamp``, ``tag``, ``level``, ``description`` per the
            Wazuh API contract. Empty list on non-200 or malformed
            payload (best-effort: callers like ``wazuh_health()``
            must not crash on a transiently-degraded manager).
        """
        from urllib.parse import urlencode

        params: dict[str, str] = {"limit": str(limit)}
        if level is not None:
            params["level"] = level
        if tag is not None:
            params["tag"] = tag
        if search is not None:
            params["search"] = search
        path = f"/manager/logs?{urlencode(params)}"
        status, body, _ = await self._request("GET", path)
        if status != 200:
            return []
        import json

        try:
            payload = json.loads(body)
        except Exception:  # noqa: BLE001
            return []
        # Wazuh 4.x shape: {"data": {"affected_items": [...]}, "error": 0}
        items = payload.get("data", {}).get("affected_items", [])
        if not isinstance(items, list):
            return []
        return [item for item in items if isinstance(item, dict)]

    # Core Wazuh daemons that MUST be "running" before we consider the
    # manager fully restarted. Others (csyslogd, agentlessd, dbd,
    # integratord, maild, reportd, clusterd) are intentionally stopped
    # on most deployments and would otherwise pin poll_restart to a
    # permanent timeout. W-NEW-5 (2026-05-12): observed on live
    # WAZUH-HOST — the manager finished restart in <60s but
    # `all running` gate never released because csyslogd/clusterd/etc
    # were stopped by design. Verified via direct /manager/status:
    # analysisd/remoted/modulesd/apid all transitioned running→running.
    _CORE_DAEMONS: frozenset[str] = frozenset({
        "wazuh-analysisd",
        "wazuh-apid",
        "wazuh-db",
        "wazuh-execd",
        "wazuh-logcollector",
        "wazuh-modulesd",
        "wazuh-monitord",
        "wazuh-remoted",
        "wazuh-syscheckd",
    })

    def _required_daemons(self, cluster_mode: bool) -> frozenset[str]:
        """Resolve the daemon set whose ``running`` state gates restart.

        W-NEW-8 (2026-05-12): on HA cluster deployments,
        ``wazuh-clusterd`` is load-bearing (it brokers config sync +
        agent-key replication across nodes); promote it into the core
        set. On single-node deployments ``clusterd`` is intentionally
        stopped and stays excluded.
        """
        if cluster_mode:
            return self._CORE_DAEMONS | frozenset({"wazuh-clusterd"})
        return self._CORE_DAEMONS

    @staticmethod
    def _item_all_running(item: dict, required: frozenset[str]) -> bool:
        """True iff every required daemon in *item* reports ``running``.

        ``item.get(name)`` returns ``None`` for missing keys, which
        is ``!= "running"`` and correctly fails — matches the
        W-NEW-5-fix semantics that absence is not-yet-running.
        """
        return all(item.get(name) == "running" for name in required)

    async def _poll_collect_node_items(
        self, cluster_mode: bool
    ) -> tuple[list[dict], bool]:
        """Return the per-node manager-status items for the current poll.

        On single-node: one call to ``/manager/status``, returning its
        ``affected_items`` list (typically length 1).

        On cluster: enumerates nodes via ``/cluster/nodes`` and queries
        each node's status. If the node list is empty or any node
        returns no items, returns ``([], False)`` so the caller treats
        the iteration as a wait, not a pass.

        Returns ``(items, ok)`` where ``ok`` is False on TLS/transient
        failure so the caller skips this poll without treating it as a
        gate release.
        """
        if not cluster_mode:
            try:
                status = await self.get_manager_status()
            except TLSFailure:
                return [], False
            data = status.get("data") if isinstance(status, dict) else None
            items = data.get("affected_items") if isinstance(data, dict) else None
            if not isinstance(items, list):
                return [], True
            return [item for item in items if isinstance(item, dict) and item], True

        # Cluster path: per-node enumerate + query.
        try:
            names = await self.get_cluster_node_names()
        except TLSFailure:
            return [], False
        if not names:
            # Cluster reported enabled but no nodes — treat as transient.
            return [], False
        items: list[dict] = []
        for name in names:
            try:
                node_status = await self.get_cluster_node_status(name)
            except TLSFailure:
                return [], False
            data = node_status.get("data") if isinstance(node_status, dict) else None
            node_items = data.get("affected_items") if isinstance(data, dict) else None
            if not isinstance(node_items, list) or not node_items:
                # A node reporting empty/malformed status means we can't
                # claim the cluster is healthy yet; treat as wait.
                return [], True
            # Each node should return exactly one item with its daemon
            # map; defensive — flatten to a single per-node dict.
            merged: dict[str, str] = {}
            for n_item in node_items:
                if isinstance(n_item, dict):
                    for k, v in n_item.items():
                        if isinstance(k, str) and isinstance(v, str):
                            merged[k] = v
            if not merged:
                return [], True
            items.append(merged)
        return items, True

    async def poll_restart(self, timeout_sec: int = 90) -> None:
        """Poll manager status until running or timeout.

        F-14: ±20% jitter applied to each sleep so multiple concurrent
        push runs don't synchronise their poll requests.

        W-NEW-5 / W-NEW-5-fix: only the daemons in the result of
        :pyfunc:`_required_daemons` must be ``running``; optional
        daemons that are intentionally stopped (csyslogd, agentlessd,
        ``clusterd`` on single-node, etc.) are ignored. Missing core
        daemons are treated as not-yet-running and polling continues.

        W-NEW-8 (2026-05-12): cluster-aware. On HA cluster deployments
        (``is_cluster_enabled()`` true once at loop entry — cluster mode
        is stable across a restart window), the gate evaluates every
        node independently via ``/cluster/{node}/status``; **every node
        must pass** before the gate releases. ``wazuh-clusterd`` is
        promoted into the required-daemon set when cluster mode is
        detected. Also fixes the last-write-wins flatten that masked a
        non-running daemon when a later item in ``affected_items``
        reported the same daemon as running — now each item is
        evaluated independently and every item must pass.
        """
        import random

        # Detect cluster mode once at loop entry; it does not toggle
        # mid-restart in practice and the per-iteration call would add
        # latency. Failures default to single-node (safe under-set).
        cluster_mode = False
        try:
            cluster_mode = await self.is_cluster_enabled()
        except TLSFailure:
            logger.info("cluster-mode probe TLSFailure; defaulting to single-node")
        required = self._required_daemons(cluster_mode)
        logger.debug(
            "poll_restart cluster_mode=%s required_daemons=%s",
            cluster_mode,
            sorted(required),
        )

        deadline = time.monotonic() + timeout_sec
        poll_interval = 2.0
        elapsed = 0.0
        attempt = 0
        while time.monotonic() < deadline:
            attempt += 1
            items, ok = await self._poll_collect_node_items(cluster_mode)
            # ok=False → transient TLS / empty node list; skip without
            # claiming gate release.
            if ok and items:
                # Every item (per-node on cluster, single item on
                # single-node) must independently pass — closes the
                # last-write-wins flatten bug class.
                all_pass = all(
                    self._item_all_running(item, required) for item in items
                )
                if all_pass:
                    logger.info(
                        "Wazuh manager %s daemons running after %.1fs (attempt %d, cluster=%s, nodes=%d)",
                        "cluster" if cluster_mode else "core",
                        elapsed,
                        attempt,
                        cluster_mode,
                        len(items),
                    )
                    return

            jittered = poll_interval * (0.8 + random.random() * 0.4)
            await asyncio.sleep(jittered)
            elapsed += jittered
            # After 30s, switch to 5s polling
            if elapsed > 30:
                poll_interval = 5.0

        raise RestartTimeoutError(f"Wazuh manager restart polling timed out after {timeout_sec}s")
