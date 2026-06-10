"""FastMCP stdio server exposing SIFT's 38 in-process tools as a real MCP server.

BMAD-M8 Phase M8.4a — addresses the Goal 1 critique that SIFT's MCP boundary
was an in-process Python module rather than a Model Context Protocol server.
Every tool here is a thin FastMCP route over the existing `mcp_*` async
functions in :mod:`mcp_server.server`. The Pydantic typing, Thymus policy,
rate limiting, and `@traced` instrumentation already on the inner functions
flow through unchanged — this module is *only* the protocol surface.

Run as:

    python -m agentropix_mcp.fastmcp_app

The server speaks MCP stdio. Pair with Claude Desktop / Claude Code
``mcp.json`` to expose 37 forensic + analysis tools to a remote LLM:

    {
      "mcpServers": {
        "agentropix-sift": {
          "command": "python",
          "args": ["-m", "agentropix_mcp.fastmcp_app"]
        }
      }
    }

Notes:
  * FastMCP is an OPTIONAL dependency. The module imports it lazily so
    SIFT's main pytest suite (which never spins up the MCP protocol)
    keeps zero new external imports. Install with ``pip install fastmcp``
    when you actually want the protocol surface.
  * Each tool's signature mirrors the inner ``mcp_*`` function so the
    existing tests + Pydantic schemas still validate the wire format.
  * Tool docstrings carry the parameter contract — FastMCP exposes them
    as the tool description to the calling LLM.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import logging.handlers
import os
import secrets
import shutil as _shutil
import tempfile
import time
import warnings
from pathlib import Path

from agentropix_mcp import __version__ as _SIFT_VERSION
from agentropix_mcp import server as _inner
from agentropix_mcp._startup_banner import log_active_configuration
from agentropix_mcp._tool_pins import verify_pins

# Bug B hardening (2026-04-25). Cap concurrent ``extract_files``
# invocations so a single slow ifind/icat can't amplify into a server-
# wide back-pressure event. Tunable via env var; floor 1, ceiling 16.
_EXTRACT_CONCURRENCY = max(1, min(16, int(os.environ.get("AGENTROPIX_EXTRACT_CONCURRENCY", "4"))))
_extract_semaphore: asyncio.Semaphore | None = None


def _get_extract_semaphore() -> asyncio.Semaphore:
    """Lazy-construct the semaphore so it binds to the running event loop."""
    global _extract_semaphore
    if _extract_semaphore is None:
        _extract_semaphore = asyncio.Semaphore(_EXTRACT_CONCURRENCY)
    return _extract_semaphore


logger = logging.getLogger(__name__)


# W-116: dependency health check. Each external binary the wrappers shell
# out to is validated at startup so missing tooling shows up as a banner
# warning rather than a runtime tool_available=false silently degrading
# every call. AGENTROPIX_*_TOOL env vars are honored where applicable.
_REQUIRED_BINARIES: list[tuple[str, str | None, str]] = [
    ("AppCompatCacheParser", "AGENTROPIX_SHIMCACHE_TOOL", "https://ericzimmerman.github.io/"),
    ("AmcacheParser", "AGENTROPIX_AMCACHE_TOOL", "https://ericzimmerman.github.io/"),
    ("evtx_dump", "AGENTROPIX_EVTX_TOOL", "https://github.com/omerbenamram/evtx/releases"),
    ("vol", None, "uv pip install volatility3"),
    ("yara", None, "apt install yara"),
    ("rip.pl", None, "apt install regripper"),
    ("bulk_extractor", None, "apt install bulk-extractor"),
]


# EZ Tools invoked via `dotnet <dll>` rather than direct PATH binaries.
# Phase 1 EZ Tools integration (W-125 RECmd / W-126 MFTECmd / W-127 LECmd).
_REQUIRED_DOTNET_TOOLS: list[tuple[str, str, str, str]] = [
    (
        "RECmd",
        "AGENTROPIX_RECMD_DLL",
        "/opt/ezt/net9/RECmd/RECmd.dll",
        "https://ericzimmerman.github.io/ (net9 zip)",
    ),
    (
        "MFTECmd",
        "AGENTROPIX_MFTECMD_DLL",
        "/opt/ezt/net9/MFTECmd/MFTECmd.dll",
        "https://ericzimmerman.github.io/ (net9 zip)",
    ),
    (
        "LECmd",
        "AGENTROPIX_LECMD_DLL",
        "/opt/ezt/net9/LECmd/LECmd.dll",
        "https://ericzimmerman.github.io/ (net9 zip)",
    ),
]


def _check_dependencies() -> None:
    for binary, env_var, install_hint in _REQUIRED_BINARIES:
        resolved = os.environ.get(env_var) if env_var else None
        name = resolved or binary
        path = _shutil.which(name)
        if path:
            logger.info("dependency OK      %-30s -> %s", name, path)
        else:
            logger.warning(
                "dependency MISSING %-30s (tool_available=false for dependent tools); install: %s",
                name,
                install_hint,
            )
    # W-137 §4.1: SHA-256 pin verification. Runs after the dependency
    # presence-check above so a missing binary still surfaces with its
    # install hint rather than as a "skipped" pin line. ``verify_pins``
    # honors AGENTROPIX_VERIFY_TOOL_PINS=off|warn|strict; in strict mode
    # it raises ``ToolPinMismatchError`` and aborts startup.
    verify_pins()
    dotnet_path = _shutil.which("dotnet")
    if not dotnet_path:
        logger.warning(
            "dependency MISSING %-30s (EZ Tools wrappers degrade); install: apt install dotnet-runtime-9.0",  # noqa: E501
            "dotnet",
        )
        return
    for label, env_var, default_dll, install_hint in _REQUIRED_DOTNET_TOOLS:
        dll_path = os.environ.get(env_var) or default_dll
        if Path(dll_path).is_file():
            logger.info("dependency OK      %-30s -> dotnet %s", label, dll_path)
        else:
            logger.warning(
                "dependency MISSING %-30s (DLL not found at %s); install: %s",
                label,
                dll_path,
                install_hint,
            )


def _configure_logging(log_dir: Path = Path("/var/log/agentropix")) -> None:
    """Configure split logging: file (all levels) + console (WARNING+ only).

    Phase 1 fix for operations risk: users only see clean output on console
    while operators can debug via /var/log/agentropix/server.log.
    """
    log_dir.mkdir(parents=True, exist_ok=True)

    # File handler: capture everything for forensics
    file_handler = logging.handlers.RotatingFileHandler(
        log_dir / "server.log",
        maxBytes=104857600,  # 100 MB
        backupCount=10,
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    )

    # Console handler: WARNING+ only (clean user output)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(logging.Formatter("%(message)s"))

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    # Suppress framework noise
    logging.getLogger("mcp.server").setLevel(logging.WARNING)
    logging.getLogger("mcp.server.lowlevel").setLevel(logging.WARNING)
    logging.getLogger("uvicorn").setLevel(logging.WARNING)
    logging.getLogger("starlette").setLevel(logging.WARNING)
    logging.getLogger("starlette.requests").setLevel(logging.WARNING)
    logging.getLogger("fastmcp").setLevel(logging.WARNING)


def _get_auth_token() -> str | None:
    """Return bearer token from env, or None if not set.

    Phase 1 fix for security risk: every HTTP POST requires valid token.
    Token should be a strong random string (e.g., 32+ bytes base64-encoded).
    """
    return os.environ.get("AGENTROPIX_MCP_AUTH_TOKEN")


def _add_auth_middleware(app) -> None:
    """Add bearer token authentication + audit logging middleware to FastMCP app.

    Phase 1 fixes: (1) Every HTTP POST to /mcp requires valid Bearer token
    (env var AGENTROPIX_MCP_AUTH_TOKEN). (2) Every request is logged to
    /var/log/agentropix/http_audit.log as JSON.

    Fail-closed at boot (Gap 5, 2026-05-23): refuse to start when
    AGENTROPIX_MCP_AUTH_TOKEN is unset, unless AGENTROPIX_MCP_DEV_MODE=1
    is set as an explicit opt-in to unauthenticated dev mode. Prior
    behaviour silently passed every request through when the env var
    was missing — see ``fastmcp_app.py:201`` in the pre-fix code.
    """
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse

    token = _get_auth_token()
    if token is None:
        if os.environ.get("AGENTROPIX_MCP_DEV_MODE") == "1":
            warnings.warn(
                "AGENTROPIX_MCP_AUTH_TOKEN unset and AGENTROPIX_MCP_DEV_MODE=1 - "
                "MCP server is unauthenticated. NEVER use in production.",
                RuntimeWarning,
                stacklevel=2,
            )
        else:
            raise RuntimeError(
                "AGENTROPIX_MCP_AUTH_TOKEN environment variable is not set. "
                "Refusing to start: the MCP server would accept unauthenticated "
                "requests. Set the env var to a strong random token (32+ bytes), "
                "or set AGENTROPIX_MCP_DEV_MODE=1 to explicitly opt into "
                "unauthenticated dev mode."
            )
    audit_logger = _get_audit_logger()
    # SIFT-W-298 verbose access logging (2026-06-01): opt-in via
    # AGENTROPIX_MCP_ACCESS_LOG=verbose. Default OFF -> the audit JSON shape is
    # byte-for-byte unchanged, so existing parsers/tests are unaffected. When
    # ON, each /mcp request also logs client_ip (X-Forwarded-For aware for the
    # tailscale-serve / reverse-proxy hop), the MCP session_id, a per-request
    # request_id (also echoed in the X-Request-Id response header for
    # client<->server correlation), user_agent, and req/resp byte sizes.
    # The bearer token is NEVER logged — only its sha256[:16] token_hash.
    verbose_access = os.environ.get("AGENTROPIX_MCP_ACCESS_LOG", "").strip().lower() == "verbose"

    def _audit(request, token_hash, status, start_time, *, reason=None, response=None):
        rec = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "token_hash": token_hash,
            "method": request.method,
            "path": request.url.path,
            "status": status,
            "duration_ms": round((time.time() - start_time) * 1000, 1),
        }
        if reason is not None:
            rec["reason"] = reason
        if verbose_access:
            xff = request.headers.get("x-forwarded-for", "")
            rec["client_ip"] = (
                xff.split(",")[0].strip()
                if xff
                else (request.client.host if request.client else None)
            )
            rec["request_id"] = getattr(request.state, "request_id", None)
            rec["session_id"] = request.headers.get("mcp-session-id")
            rec["user_agent"] = request.headers.get("user-agent")
            rec["req_bytes"] = request.headers.get("content-length")
            if response is not None:
                rec["resp_bytes"] = response.headers.get("content-length")
        audit_logger.info(json.dumps(rec))

    class BearerTokenMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            token_hash = (
                hashlib.sha256(token.encode()).hexdigest()[:16] if token is not None else "none"
            )
            start_time = time.time()
            request_id = secrets.token_hex(8)
            request.state.request_id = request_id

            is_mcp = request.url.path == "/mcp" or request.url.path.startswith("/mcp/")
            # Only enforce on HTTP transports for /mcp endpoint
            if is_mcp:
                if token is not None:
                    auth_header = request.headers.get("Authorization", "")
                    if not auth_header.startswith("Bearer "):
                        _audit(
                            request,
                            token_hash,
                            401,
                            start_time,
                            reason="missing_authorization_header",
                        )
                        return JSONResponse(
                            {"error": "Missing or invalid Authorization header"},
                            status_code=401,
                            headers={"X-Request-Id": request_id},
                        )
                    provided_token = auth_header[7:]  # Strip "Bearer "
                    # SIFT-W-281: constant-time to defeat timing leak under --public
                    if not secrets.compare_digest(provided_token, token):
                        _audit(request, token_hash, 401, start_time, reason="invalid_bearer_token")
                        return JSONResponse(
                            {"error": "Invalid bearer token"},
                            status_code=401,
                            headers={"X-Request-Id": request_id},
                        )

            response = await call_next(request)
            response.headers["X-Request-Id"] = request_id

            # Log successful requests
            if is_mcp:
                _audit(request, token_hash, response.status_code, start_time, response=response)

            return response

    # FastMCP 3.x removed the .app shim; inject via http_app() wrap.
    # Test stubs that supply a .app attribute (pre-3.x pattern) still
    # use the legacy path so existing tests remain unchanged.
    if hasattr(app, "http_app"):
        _orig_http_app = app.http_app

        def _http_app_with_auth(*args, **kwargs):
            starlette_app = _orig_http_app(*args, **kwargs)
            starlette_app.add_middleware(BearerTokenMiddleware)
            return starlette_app

        app.http_app = _http_app_with_auth
    else:
        app.app.add_middleware(BearerTokenMiddleware)


def _get_audit_logger() -> logging.Logger:
    """Return a logger configured for HTTP audit trail.

    Phase 1 fix for security risk: audit every tool call with timestamp,
    token hash, tool name, and response status. Stored in JSON format to
    /var/log/agentropix/http_audit.log with daily rotation.

    SIFT-W-281: honors AGENTROPIX_AUDIT_LOG_DIR for test isolation and
    non-default-root deployments. Production deployments leave it unset
    and inherit the historical /var/log/agentropix path.
    """
    audit_logger = logging.getLogger("agentropix_mcp.http_audit")
    if audit_logger.handlers:
        return audit_logger

    log_dir = Path(os.environ.get("AGENTROPIX_AUDIT_LOG_DIR", "/var/log/agentropix"))
    log_dir.mkdir(parents=True, exist_ok=True)

    handler = logging.handlers.RotatingFileHandler(
        log_dir / "http_audit.log",
        maxBytes=104857600,  # 100 MB
        backupCount=10,
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    audit_logger.addHandler(handler)
    audit_logger.setLevel(logging.INFO)
    return audit_logger


def _build_app():
    """Construct the FastMCP app. Lazy import so the dependency is optional."""
    try:
        from fastmcp import FastMCP  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover  — dependency-optional path
        raise RuntimeError(
            "fastmcp is not installed. Install with `pip install fastmcp` "
            "to use the protocol-surface MCP server."
        ) from exc

    app = FastMCP("agentropix-sift")
    startup_ts = time.monotonic()

    # ----------------------------------------------------------------- #
    # Health probe (W-134)                                               #
    # ----------------------------------------------------------------- #
    @app.tool()
    async def health() -> dict:
        """Lightweight server health probe — no subprocess I/O, no Thymus, no rate-limit (W-134).

        Returns server name, version, uptime, and the live count of
        registered MCP tools. Operators and orchestrators (Trinity,
        Critic, scripts/probe_mcp.py) probe this instead of invoking a
        full forensic tool as a canary. Cheaper than ``get_image_info``
        (~30 ms canary) — no subprocess.

        The ``tool_count`` field is the single source of truth for
        downstream documentation; narrative docs (ABOUT-THE-PROJECT,
        macro reports) should cite this endpoint rather than hardcode
        the catalogue size, which drifts as wrappers are added.
        """
        tools = await app.list_tools()
        return {
            "status": "ok",
            "server": "agentropix-sift",
            "version": _SIFT_VERSION,
            "uptime_seconds": round(time.monotonic() - startup_ts, 3),
            "tool_count": len(tools),
        }

    # ----------------------------------------------------------------- #
    # Volatility 3                                                       #
    # ----------------------------------------------------------------- #
    @app.tool()
    async def get_pslist(image: str, pid_filter: list[int] | None = None) -> dict:
        """Volatility3 windows.pslist — process list with PID filter."""
        result = await _inner.mcp_get_pslist(image, pid_filter=pid_filter)
        return result.model_dump()

    @app.tool()
    async def run_volatility(
        target: str,
        plugin: str,
        args: dict[str, object] | None = None,
        timeout_seconds: int | None = None,
    ) -> dict:
        """Run any allowlisted Volatility3 windows.* plugin (W-098).

        Generic escape hatch exposing the top-20 vol3 plugins through a
        single tool. ``plugin`` accepts short aliases (``"malfind"``,
        ``"netscan"``, ``"cmdline"`` …) or canonical ids
        (``"windows.malfind.Malfind"``). ``args`` flattens to
        plugin-specific CLI flags (``{"pid": 4732}`` →
        ``--pid 4732``; ``{"dump": True}`` → ``--dump``). Returns a
        ``VolatilityReport`` whose ``rows`` preserves vol3's JSON
        output verbatim. ``timeout_seconds`` overrides the default
        ``AGENTROPIX_VOL3_TIMEOUT`` (600s, floor 5, ceiling 3700).
        """
        result = await _inner.mcp_run_volatility(
            target,
            plugin,
            args=args,
            timeout_seconds=timeout_seconds,
        )
        return result.model_dump()

    @app.tool()
    async def get_netscan(image: str) -> dict:
        """Volatility3 windows.netscan — typed TCP/UDP socket list (W-140).

        Uses the -r csv renderer for reliable output on all tested images.
        Returns NetscanReport with SocketInfo rows: proto, local_addr,
        local_port, foreign_addr, foreign_port, state, pid, owner.
        Prefer this over run_volatility("netscan") for typed output.
        """
        result = await _inner.mcp_get_netscan(image)
        return result.model_dump()

    @app.tool()
    async def get_malfind(image: str) -> dict:
        """Volatility3 windows.malfind — injected code / RWX VAD detection (W-140).

        Uses the -r csv renderer. Returns MalfindReport with MalfindHit
        rows: pid, process, address, vad_tag, protection, commit_charge,
        private_memory, hexdump_head (first 120 chars of hex output).
        Prefer this over run_volatility("malfind") for typed output.
        """
        result = await _inner.mcp_get_malfind(image)
        return result.model_dump()

    @app.tool()
    async def get_svcscan(image: str) -> dict:
        """Volatility3 windows.svcscan — Windows service enumeration (W-140).

        Pool-tag scan for Service Control Manager entries. More robust
        than pslist-based approaches on paused-VM or corrupted images.
        Returns SvcscanReport with ServiceInfo rows: pid, name, display,
        state, start, type, binary, dll.
        Prefer this over run_volatility("svcscan") for typed output.
        """
        result = await _inner.mcp_get_svcscan(image)
        return result.model_dump()

    @app.tool()
    async def get_editbox(
        image: str,
        profile: str | None = None,
        timeout_seconds: float | None = None,
        max_records: int | None = None,
    ) -> dict:
        """Vol2.6 editbox plugin — recover Edit-control widget contents (W-209).

        TeamSpy-class credential recovery: walks Win32k USER objects to
        recover typed credentials (TeamViewer / RDP / IM) still resident
        in memory.  Drives the legacy Vol2.6.1 plugin out-of-process
        through a Python 2.7 sandbox (Vol3 never gained an editbox
        port).  Install the sandbox per docs/runbooks/vol26-install.md
        before first call.

        `profile` validates against [A-Za-z0-9_]+ (argv-injection guard).
        `timeout_seconds` overrides AGENTROPIX_EDITBOX_TIMEOUT_S
        (default 600, floor 60, ceiling 7200).  `max_records` overrides
        AGENTROPIX_EDITBOX_MAX_RECORDS (default 10000).
        """
        result = await _inner.mcp_get_editbox(
            image,
            profile=profile,
            timeout_seconds=timeout_seconds,
            max_records=max_records,
        )
        return result.model_dump()

    # ----------------------------------------------------------------- #
    # Plaso / log2timeline                                               #
    # ----------------------------------------------------------------- #
    @app.tool()
    async def get_timeline(
        image: str,
        parsers: str | None = None,
        max_events: int = 2000,
    ) -> dict:
        """Plaso log2timeline + psort — super-timeline with two-pass priority sampler.

        ``parsers`` is a comma-separated subset of plaso parsers (default
        winevtx,winreg,prefetch,scheduled_tasks,filestat,winjob,mft).
        ``max_events`` caps the post-sampler output (default 2000).
        Honors AGENTROPIX_PLASO_EXCLUDE_FAMILIES env-var to skip noisy
        parsers up-front (M8.4c).
        """
        result = await _inner.mcp_get_timeline(image, parsers=parsers, max_events=max_events)
        return result.model_dump()

    # ----------------------------------------------------------------- #
    # The Sleuth Kit (TSK)                                               #
    # ----------------------------------------------------------------- #
    @app.tool()
    async def fls(
        image: str,
        offset: int = 0,
        inode: str | None = None,
        recursive: bool = True,
        deleted_only: bool = False,
        fstype: str | None = None,
        summary_only: bool = False,
    ) -> dict:
        """TSK fls — list files (incl. deleted; T1070.004 surface).

        ``offset`` is the partition offset in sectors. Default 0 means
        "the whole image is one partition" (or "use mmls to find it"
        depending on the inner wrapper). Default-int rather than int|None
        avoids a Pydantic validation error when a Claude Desktop client
        sends ``offset: null`` over the wire — the inner ``FileListing``
        model declares ``offset: int`` strictly. ``summary_only=True``
        (NIST1 ISSUE-002) returns entry_count but omits the entries list so
        large recursive listings fit the result envelope.
        """
        result = await _inner.mcp_fls(
            image,
            offset=offset,
            inode=inode,
            recursive=recursive,
            deleted_only=deleted_only,
            fstype=fstype,
            summary_only=summary_only,
        )
        return result.model_dump()

    @app.tool()
    async def get_partitions(image: str) -> dict:
        """TSK mmls — enumerate a disk image's partition table (NIST1 ISSUE-001).

        Returns partition rows plus ``filesystem_offsets`` (start sectors) so a
        caller can feed ``fls(offset=...)`` / ``extract_files`` on a physical-disk
        image instead of guessing offset 0 (which lands on the MBR and fails FS
        detection). Raises an actionable error when there is no partition table
        (single-volume image → try ``fls`` offset 0).
        """
        result = await _inner.mcp_get_partitions(image)
        return result.model_dump()

    @app.tool()
    async def get_evt(
        source: str,
        mode: str = "items",
        max_events: int | None = None,
        summary_only: bool = False,
    ) -> dict:
        """Legacy Windows ``.evt`` EventLog parser (XP/2003) via libevt evtexport
        (NIST1 ISSUE-008). Covers the binary ``.evt`` that ``get_evtx`` N/As on
        (Application/Security/System.evt under WINDOWS\\system32\\config). Pass an
        extracted ``.evt`` path; returns normalised event rows (id/source/time/
        strings). ``summary_only=True`` keeps event_count, omits the events list.
        """
        result = await _inner.mcp_get_evt(
            source, mode=mode, max_events=max_events, summary_only=summary_only
        )
        return result.model_dump()

    @app.tool()
    async def extract_files(
        image: str,
        paths: list[str | int],
        dest: str | None = None,
        offset: int = 0,
        fstype: str | None = None,
        follow_reparse_points: bool = True,
        expand_dirs: bool = False,
        max_dir_files: int | None = None,
    ) -> dict:
        """TSK ifind+icat — extract in-container paths to a tempdir.

        ``dest`` is the destination directory the extracted files land
        in. The inner ``mcp_extract_files`` requires a Thymus-allowed
        write zone (per ADR-012, the prefix ``/tmp/agentropix-sift-*``
        is auto-allowed). When the caller omits ``dest`` — the typical
        Claude Desktop call shape — this wrapper auto-creates a fresh
        ``tempfile.mkdtemp(prefix="agentropix-sift-extract-")`` so the
        client doesn't have to know about the policy. The chosen path
        is surfaced in the returned manifest's per-file ``dest`` keys
        so downstream tools (``get_registry``, ``get_amcache`` …) can
        read the extracted hives.

        ``offset`` matches the strict-int contract on the inner wrapper;
        default 0 covers single-partition images and "auto-detect via
        mmls" cases.

        W-265: a ``paths`` entry may be an integer MFT/inode number
        instead of a string path. It is streamed directly via ``icat``
        (skipping ``ifind`` path resolution), lands at ``inode-<N>`` in
        ``dest``, and is flagged ``inode_only`` in the manifest. Use when
        the caller already knows the inode (e.g. a DPAPI master key cited
        by MFT entry) and a path lookup is unnecessary or impossible.

        W-255 ``follow_reparse_points`` (default True): when an ``ifind``
        miss occurs on a path containing a known Windows junction
        segment (``My Documents``, ``Local Settings``, ``Application
        Data``, ``Documents and Settings`` …), retry once with the
        canonical equivalent. The original requested path is preserved
        in the manifest's ``rewrote_from`` field; a diagnostic ``hints``
        entry is emitted either way so callers learn about the TSK
        traversal limitation. Set False for byte-for-byte path fidelity
        in workflows that must record the caller's exact request.

        Bug B hardening (2026-04-25): the auto-``mkdtemp`` is wrapped in
        ``asyncio.to_thread`` so a slow filesystem (NFS, busy disk)
        can't block the event loop. The whole call is gated by a
        per-server semaphore (``AGENTROPIX_EXTRACT_CONCURRENCY``,
        default 4) so a slow ifind/icat doesn't amplify into a
        server-wide wedge.
        """
        if dest is None:
            # mkdtemp is a syscall to ``mkdir`` — fast on local FS but
            # can stall on network mounts or mount-point creation. Wrap
            # defensively.
            dest = await asyncio.to_thread(tempfile.mkdtemp, prefix="agentropix-sift-extract-")
        sem = _get_extract_semaphore()
        async with sem:
            result = await _inner.mcp_extract_files(
                image,
                paths=paths,
                dest=dest,
                offset=offset,
                fstype=fstype,
                follow_reparse_points=follow_reparse_points,
                expand_dirs=expand_dirs,
                max_dir_files=max_dir_files,
            )
        return result.model_dump()

    @app.tool()
    async def extract_archive(
        archive: str,
        dest: str | None = None,
        members: list[str] | None = None,
        max_total_bytes: int | None = None,
        max_files: int | None = None,
        max_per_file_bytes: int | None = None,
        timeout_seconds: float | None = None,
        engine: str | None = None,
    ) -> dict:
        """W-095 — unpack ``.7z``/``.zip``/``.tar*`` into a Thymus-allowed dest.

        Inverse of ``_reject_archive``: gives the operator an MCP-native
        path to decompress evidence (22 FA-B reports were blocked at the
        archive boundary because the only workaround was SSH+``7z x``).
        Engine = ``7z x`` for 7z/zip/rar, ``tar -xf`` for tar/tgz/tbz/txz.

        Bomb defense: ``7z l -slt`` pre-flight refuses oversized archives
        BEFORE extraction; per-entry path-traversal + symlink-escape are
        re-checked AFTER extraction (offending entries get unlinked and
        surface as ``ok=False`` rows in the manifest).

        Caps default to env (``AGENTROPIX_ARCHIVE_MAX_BYTES`` 50 GiB,
        ``MAX_FILES`` 1M, ``MAX_PER_FILE_BYTES`` 16 GiB,
        ``TIMEOUT`` 600 s). Per-call overrides take precedence within the
        same floor/ceiling guards.

        When ``dest`` is omitted, a fresh
        ``/tmp/agentropix-sift-archive-*`` directory is auto-created
        (matches the ``extract_files`` ergonomic).
        """
        if dest is None:
            dest = await asyncio.to_thread(tempfile.mkdtemp, prefix="agentropix-sift-archive-")
        result = await _inner.mcp_extract_archive(
            archive,
            dest=dest,
            members=members,
            max_total_bytes=max_total_bytes,
            max_files=max_files,
            max_per_file_bytes=max_per_file_bytes,
            timeout=timeout_seconds,
            engine=engine,
        )
        return result.model_dump()

    # ----------------------------------------------------------------- #
    # Registry / Eric Zimmerman family                                   #
    # ----------------------------------------------------------------- #
    @app.tool()
    async def get_registry(
        hive: str, profile: str | None = None, plugin: str | None = None
    ) -> dict:
        """RegRipper rip.pl — registry hive parsing (profile or single plugin)."""
        result = await _inner.mcp_get_registry(hive, profile=profile, plugin=plugin)
        return result.model_dump()

    @app.tool()
    async def get_amcache(hive: str) -> dict:
        """Amcache.hve parser — recently-executed binary inventory."""
        result = await _inner.mcp_get_amcache(hive)
        return result.model_dump()

    @app.tool()
    async def get_shimcache(hive: str) -> dict:
        """AppCompatCache parser — execution evidence in SYSTEM hive."""
        result = await _inner.mcp_get_shimcache(hive)
        return result.model_dump()

    @app.tool()
    async def get_recmd(
        hive: str,
        batch_file: str | None = None,
        timeout_seconds: float | None = None,
    ) -> dict:
        """RECmd batch-driven registry parser (W-125, .NET).

        Complements ``get_registry`` (RegRipper / Perl) with Eric
        Zimmerman's RECmd. ``batch_file`` is a filename (resolved under
        ``AGENTROPIX_RECMD_BATCH_DIR``, default ``BatchExamples/``) or
        an absolute path to a ``.reb`` file; ``None`` selects
        ``AGENTROPIX_RECMD_BATCH`` (default ``Kroll_Batch.reb``).
        ``timeout_seconds`` overrides ``AGENTROPIX_RECMD_TIMEOUT``
        (default 120, floor 5, ceiling 3700).
        """
        result = await _inner.mcp_get_recmd(
            hive, batch_file=batch_file, timeout_seconds=timeout_seconds
        )
        return result.model_dump()

    @app.tool()
    async def get_mftecmd(
        artifact: str,
        mft: str | None = None,
        timeout_seconds: float | None = None,
    ) -> dict:
        """MFTECmd NTFS artifact parser (W-126, .NET).

        Parses $MFT, $J (USN journal), $I30 (directory index), $Boot,
        or $Secure_$SDS. ``artifact`` is the path to the extracted
        artifact file. For $J files, supply ``mft`` as the path to the
        companion $MFT file to enable parent directory path resolution.
        ``timeout_seconds`` overrides ``AGENTROPIX_MFTECMD_TIMEOUT``
        (default 180, floor 5, ceiling 3700).
        """
        result = await _inner.mcp_get_mftecmd(artifact, mft=mft, timeout_seconds=timeout_seconds)
        return result.model_dump()

    @app.tool()
    async def get_lecmd(
        target: str,
        all_files: bool = False,
        timeout_seconds: float | None = None,
    ) -> dict:
        """LECmd .lnk shortcut parser (W-127, .NET).

        Parses Windows Shell Link (.lnk) files for T1547 persistence
        evidence: target path, arguments, working directory, icon
        location, and timestamps. ``target`` is a single .lnk file
        (``-f`` mode) or a directory (``-d`` mode; LECmd recurses
        automatically). ``all_files=True`` adds ``--all`` to include
        non-``.lnk`` files when scanning a directory.
        ``timeout_seconds`` overrides ``AGENTROPIX_LECMD_TIMEOUT``
        (default 120, floor 5, ceiling 3700).
        """
        result = await _inner.mcp_get_lecmd(
            target, all_files=all_files, timeout_seconds=timeout_seconds
        )
        return result.model_dump()

    @app.tool()
    async def get_jlecmd(
        target: str,
        all_files: bool = False,
        timeout_seconds: float | None = None,
    ) -> dict:
        """JLECmd Jump-List parser (Phase 2, .NET).

        Parses Windows Jump List files (``*.automaticDestinations-ms``
        and ``*.customDestinations-ms``) for taskbar / Start-menu
        recently-opened evidence. ``target`` is a single Jump-List
        file (``-f``) or a directory (``-d``); ``all_files=True``
        widens the directory scan beyond the default extensions.
        ``timeout_seconds`` overrides ``AGENTROPIX_JLECMD_TIMEOUT``
        (default 120, floor 5, ceiling 3700).
        """
        result = await _inner.mcp_get_jlecmd(
            target, all_files=all_files, timeout_seconds=timeout_seconds
        )
        return result.model_dump()

    @app.tool()
    async def get_sbecmd(
        hive_dir: str,
        timeout_seconds: float | None = None,
    ) -> dict:
        """SBECmd ShellBags parser (Phase 2, .NET).

        Parses NTUSER.DAT / UsrClass.dat hives for ShellBag
        folder-navigation history. ``hive_dir`` is a directory
        containing one or more registry hives (SBECmd is
        directory-only by design). ``timeout_seconds`` overrides
        ``AGENTROPIX_SBECMD_TIMEOUT`` (default 180, floor 5,
        ceiling 3700).
        """
        result = await _inner.mcp_get_sbecmd(hive_dir, timeout_seconds=timeout_seconds)
        return result.model_dump()

    @app.tool()
    async def get_sqlecmd(
        target: str,
        hunt: bool = False,
        no_blob: bool = True,
        sample_per_schema: int | None = None,
        timeout_seconds: float | None = None,
    ) -> dict:
        """SQLECmd SQLite parser (Phase 2, .NET).

        Parses SQLite databases against the EZ Tools SQL maps library
        (95+ schemas: Chrome / Firefox / Edge browser history, Windows
        AppCompat, Skype / Slack / Teams, Android, more). Auto file
        (-f) vs directory (-d) mode. ``hunt=True`` enables SQLite-
        header sniffing in directory mode (catches DBs with non-
        standard extensions). ``no_blob=True`` (default) drops blob
        payloads to bound CSV size. ``sample_per_schema`` caps rows
        kept per produced schema in ``sampled_rows`` (default 100).
        ``timeout_seconds`` overrides ``AGENTROPIX_SQLECMD_TIMEOUT``
        (default 600, floor 5, ceiling 3700).
        """
        result = await _inner.mcp_get_sqlecmd(
            target,
            hunt=hunt,
            no_blob=no_blob,
            sample_per_schema=sample_per_schema,
            timeout_seconds=timeout_seconds,
        )
        return result.model_dump()

    @app.tool()
    async def get_bstrings(
        target: str,
        look_for_string: str | None = None,
        look_for_regex: str | None = None,
        min_length: int | None = None,
        summary_only: bool = False,
        timeout_seconds: float | None = None,
    ) -> dict:
        """bstrings regex-backed string extractor (Phase 2, .NET).

        Augments GNU strings with regex-driven search (``look_for_regex``)
        and literal-substring filtering (``look_for_string``). The two
        filters are mutually exclusive — pass at most one; no filter
        = behaves like GNU strings. ``target`` is a single file (``-f``)
        or a directory (``-d``); ``min_length`` floors string length
        (default 4, AGENTROPIX_BSTRINGS_MIN_LENGTH). ``timeout_seconds``
        overrides ``AGENTROPIX_BSTRINGS_TIMEOUT`` (default 600s).
        """
        result = await _inner.mcp_get_bstrings(
            target,
            look_for_string=look_for_string,
            look_for_regex=look_for_regex,
            min_length=min_length,
            summary_only=summary_only,
            timeout_seconds=timeout_seconds,
        )
        return result.model_dump()

    @app.tool()
    async def get_prefetch(target: str) -> dict:
        """Windows Prefetch parser — execution evidence."""
        result = await _inner.mcp_get_prefetch(target)
        return result.model_dump()

    @app.tool()
    async def srum_extract(
        srudb_path: str,
        tables: list[str] | None = None,
        since_iso: str | None = None,
        limit: int = 1000,
        include_idmap: bool = False,
        timeout_seconds: float | None = None,
    ) -> dict:
        """SRUM parser — per-process network bytes, app resource usage, push
        notifications, and energy usage from ``C:\\Windows\\System32\\sru\\SRUDB.dat``.

        Linux-native via libesedb's ``esedbexport`` (SrumECmd refuses to
        run on non-Windows hosts; ``srum-dump`` requires pywin32). Tolerates
        per-table libesedb failures on dirty-shutdown SRUDBs — partial
        results land in ``tables_returned`` with the failed names in
        ``tables_failed``.

        Default ``limit=1000`` + ``include_idmap=False`` are sized so a
        full 5-table run stays under the 1 MB tool-result cap enforced
        by some MCP clients (Claude Desktop). Per-row ``app_id`` /
        ``user_sid`` fields are already resolved against the IdMap, so
        callers typically don't need the raw mapping; pass
        ``include_idmap=True`` to surface it.

        Args:
            srudb_path: Absolute path to a ``SRUDB.dat`` file.
            tables: Restrict to ``{network_data, app_resource,
                network_connectivity, push_notifications, energy_usage}``.
                ``None`` returns all five.
            since_iso: ISO-8601 cutoff for ``TimeStamp`` filtering.
            limit: Per-table row cap (max 50000, default 1000).
            include_idmap: When ``True``, surface the raw numeric-id →
                decoded-string map in ``id_lookup``. Adds 200-500 KB on
                real SRUDBs; default ``False``.
            timeout_seconds: Per-table esedbexport timeout. Defaults to
                ``AGENTROPIX_SRUM_TIMEOUT`` (600s, floor 5s, ceiling 3600s).
        """
        result = await _inner.mcp_srum_extract(
            srudb_path,
            tables=tables,
            since_iso=since_iso,
            limit=limit,
            include_idmap=include_idmap,
            timeout_seconds=timeout_seconds,
        )
        return result.model_dump()

    # ----------------------------------------------------------------- #
    # SIFT-W-289: case-lifecycle tools (4 of the 13 P0 from the         #
    # Valhuntir-on-Wazuh SYNTHESIS).                                    #
    # ----------------------------------------------------------------- #

    @app.tool()
    async def case_init(
        case_name: str,
        examiner_id: str,
        case_id: str | None = None,
        description: str = "",
        incident_type: str = "",
        severity: str = "",
        scope: str = "",
        team: list[str] | None = None,
        tags: list[str] | None = None,
        case_dir: str = "",
    ) -> dict:
        """Create a new case + update the active-case pointer.

        Writes one document to ``agentropix-cases`` keyed on
        ``case_id`` (idempotent under re-run). Updates the local
        pointer at ``~/.agentropix/active_case`` so subsequent
        tools (record_finding, report_generate, …) resolve the
        case automatically.

        Args:
            case_name: human-readable label, e.g. "Ransomware
                Investigation — May 2026".
            examiner_id: required; stamped into the case doc and
                every future evidence/approval record for
                chain-of-custody.
            case_id: optional slug. Auto-generates to
                ``INC-YYYY-MMDDHHMMSS`` when ``None``.
        """
        result = await _inner.mcp_case_init(
            case_name=case_name,
            examiner_id=examiner_id,
            case_id=case_id,
            description=description,
            incident_type=incident_type,
            severity=severity,
            scope=scope,
            team=team,
            tags=tags,
            case_dir=case_dir,
        )
        return result.model_dump()

    @app.tool()
    async def case_activate(case_id: str) -> dict:
        """Switch the active-case pointer at ``~/.agentropix/active_case``."""
        result = await _inner.mcp_case_activate(case_id)
        if hasattr(result, "model_dump"):
            return result.model_dump()
        return result  # already a dict

    @app.tool()
    async def case_status(case_id: str | None = None) -> dict:
        """Aggregate the agentropix-cases row + per-sibling-index doc
        counts (findings / timeline / evidence / iocs / approvals).

        Resolves the active-case pointer when ``case_id`` is ``None``.
        Degrades gracefully when the indexer is unreachable —
        ``indexer_reachable=False`` + ``error=...`` instead of raising.
        """
        result = await _inner.mcp_case_status(case_id)
        return result.model_dump()

    @app.tool()
    async def evidence_register(
        path: str,
        description: str,
        examiner_id: str,
        case_id: str | None = None,
    ) -> dict:
        """SHA-256 hash an evidence file and register it under the active case.

        The evidence_id is deterministic over ``(case_id, path,
        sha256)`` — re-registering the same file under the same case
        produces the same id, so accidental duplicates collapse.
        Each registration still writes a fresh row in the daily
        ``agentropix-evidence-YYYY.MM.DD`` index so chain-of-custody
        events are preserved.
        """
        result = await _inner.mcp_evidence_register(
            path=path,
            description=description,
            examiner_id=examiner_id,
            case_id=case_id,
        )
        return result.model_dump()

    # ----------------------------------------------------------------- #
    # SIFT-W-290: idx_* query + ingest tools (5 of the 13 P0).          #
    # ----------------------------------------------------------------- #

    @app.tool()
    async def idx_search(
        query: dict | None = None,
        case_id: str | None = None,
        index_pattern: str = "agentropix-findings-*",
        limit: int = 50,
        offset: int = 0,
    ) -> dict:
        """Case-scoped full-text + structured search across an
        ``agentropix-*`` sibling index.

        Internally pages over the 500-row per-call cap so a caller
        asking ``limit=2000`` gets 4 sequential round-trips assembled
        into one result. Total cap 5000 to defend the MCP tool-result
        envelope. Sorted by ``@timestamp`` descending.

        Args:
            query: bare clause (e.g. ``{"match": {"summary": "lsass"}}``)
                or full body with ``"query"`` key. ``None`` ⇒ match_all.
            case_id: optional; resolves the active-case pointer when
                ``None``.
            index_pattern: defaults to ``agentropix-findings-*``.
        """
        result = await _inner.mcp_idx_search(
            query=query,
            case_id=case_id,
            index_pattern=index_pattern,
            limit=limit,
            offset=offset,
        )
        return result.model_dump()

    @app.tool()
    async def idx_aggregate(
        field: str,
        case_id: str | None = None,
        index_pattern: str = "agentropix-findings-*",
        query: dict | None = None,
        top_n: int = 25,
    ) -> dict:
        """Top-N terms aggregation on a case-scoped index.

        Common patterns: ``mitre_techniques`` (top techniques),
        ``host.name`` (busiest hosts), ``severity`` (severity mix).
        """
        result = await _inner.mcp_idx_aggregate(
            field=field,
            case_id=case_id,
            index_pattern=index_pattern,
            query=query,
            top_n=top_n,
        )
        return result.model_dump()

    @app.tool()
    async def idx_timeline(
        case_id: str | None = None,
        index_pattern: str = "agentropix-timeline-*",
        query: dict | None = None,
        interval: str = "1h",
        time_field: str = "@timestamp",
    ) -> dict:
        """``date_histogram`` bucketing across a case-scoped index.

        Args:
            interval: OpenSearch interval shorthand
                (``1m``/``5m``/``1h``/``1d`` use fixed-interval;
                ``1w``/``1M`` use calendar-interval).
        """
        result = await _inner.mcp_idx_timeline(
            case_id=case_id,
            index_pattern=index_pattern,
            query=query,
            interval=interval,
            time_field=time_field,
        )
        return result.model_dump()

    @app.tool()
    async def idx_case_summary(case_id: str | None = None) -> dict:
        """Case overview: per-index doc counts + top hosts +
        top artifact types + time range + next-step hints.

        Mirrors Valhuntir's first-call-of-the-investigation pattern.
        Returns ``next_step_hints`` strings that suggest the next
        idx_* call based on what's already indexed.
        """
        result = await _inner.mcp_idx_case_summary(case_id=case_id)
        return result.model_dump()

    # ----------------------------------------------------------------- #
    # SIFT-W-291: record / approve / report tools (final 4 of 13 P0).   #
    # ----------------------------------------------------------------- #

    @app.tool()
    async def record_finding(
        finding: dict,
        case_id: str | None = None,
        dry_run: bool = True,
        mutation_token: str | None = None,
    ) -> dict:
        """Stage a single finding as DRAFT.

        Single-doc convenience wrapper over the same pipeline as
        ``wazuh_index_findings``. The W-286 draft-gate strips any
        caller-supplied ``approval.*`` + stamps DRAFT + provenance —
        the LLM cannot self-approve via this surface.
        """
        result = await _inner.mcp_record_finding(
            finding=finding,
            case_id=case_id,
            dry_run=dry_run,
            mutation_token=mutation_token,
        )
        return result.model_dump()

    @app.tool()
    async def delete_finding(
        finding_id: str,
        case_id: str | None = None,
        dry_run: bool = True,
        reason: str = "",
    ) -> dict:
        """Delete a DRAFT finding to self-correct an over-count (NIST1 ISSUE-014).

        record_finding is now idempotent on (case_id, finding_id), but this tool
        lets a run remove a finding it staged in error. DRAFT-only — refuses
        APPROVED/REJECTED findings (never bypasses the examiner approval
        workflow). ``dry_run=True`` (default) previews via ``would_delete``;
        pass ``dry_run=False`` to actually delete. Every delete is audit-logged.
        """
        result = await _inner.mcp_delete_finding(
            finding_id=finding_id,
            case_id=case_id,
            dry_run=dry_run,
            reason=reason,
        )
        return result.model_dump()

    @app.tool()
    async def build_executable_registry(
        case_id: str,
        executables: list[dict],
        host: str = "",
        image: str = "",
        image_md5: str = "",
        partition_offset_sectors: int = 0,
        case_dir: str = "",
        dry_run: bool = True,
    ) -> dict:
        """Build a case's Executable Artifact Registry — MASTER-IOCS.json (EAR).

        Normalises + dedupes collected executable signals (shimcache / fls ->
        extract -> hashdeep) into one canonical DRAFT inventory with a
        recovered-vs-referenced_only split, idempotent on (case_id, sha256) /
        (case_id, image_path). DRAFT-only: no examiner approval, no
        chain-of-custody signing, no live index write. ``dry_run=True`` (default)
        previews; ``dry_run=False`` + ``case_dir`` writes MASTER-IOCS.json under
        the allowed prefix.
        """
        result = await _inner.mcp_build_executable_registry(
            case_id=case_id,
            executables=executables,
            host=host,
            image=image,
            image_md5=image_md5,
            partition_offset_sectors=partition_offset_sectors,
            case_dir=case_dir,
            dry_run=dry_run,
        )
        return result.model_dump()

    @app.tool()
    async def promote_executable_registry(
        case_id: str,
        executables: list[dict],
        host: str = "",
        image: str = "",
        image_md5: str = "",
        offset: int = 0,
        dry_run: bool = True,
        mutation_token: str | None = None,
    ) -> dict:
        """Promote a case's executable registry into agentropix-executables-* (EAR
        Phase 2). dry_run=True (default) previews; a live write (dry_run=False) is
        EvidenceGate-gated and requires a valid mutation_token. Docs ship DRAFT —
        promotion indexes for retrieval, it does not apply examiner approval."""
        result = await _inner.mcp_promote_executable_registry(
            case_id=case_id,
            executables=executables,
            host=host,
            image=image,
            image_md5=image_md5,
            offset=offset,
            dry_run=dry_run,
            mutation_token=mutation_token,
        )
        return result.model_dump()

    @app.tool()
    async def promote_iocs(
        case_id: str,
        dry_run: bool = True,
        mutation_token: str | None = None,
    ) -> dict:
        """Project a case's APPROVED-finding IOCs into agentropix-iocs-* (BUG-004).

        Flattens + dedupes APPROVED findings' iocs[] on (ioc_type, ioc_value)
        and upserts by deterministic _id, so the ``ioc`` report profile has a
        populated source. dry_run=True (default) previews the count; a live write
        (dry_run=False) is EvidenceGate-gated and needs a mutation_token.
        """
        result = await _inner.mcp_promote_iocs(
            case_id=case_id, dry_run=dry_run, mutation_token=mutation_token
        )
        return result.model_dump()

    @app.tool()
    async def exec_registry_get(case_id: str, size: int = 500) -> dict:
        """Return a case's full promoted executable inventory in one call (EAR)."""
        result = await _inner.mcp_exec_registry_get(case_id=case_id, size=size)
        return result.model_dump()

    @app.tool()
    async def exec_registry_search(
        sha256: str | None = None,
        name: str | None = None,
        category: str | None = None,
        size: int = 100,
    ) -> dict:
        """Cross-case executable pivot on hash / name / category (EAR campaign linking)."""
        result = await _inner.mcp_exec_registry_search(
            sha256=sha256, name=name, category=category, size=size
        )
        return result.model_dump()

    @app.tool()
    async def record_timeline_event(
        event: dict,
        hostname: str,
        case_id: str | None = None,
    ) -> dict:
        """Stage a single timeline event as DRAFT.

        Same DRAFT / MCP-provenance / case_id stamping as
        ``idx_ingest``'s timeline half.
        """
        result = await _inner.mcp_record_timeline_event(
            event=event, hostname=hostname, case_id=case_id
        )
        return result.model_dump()

    @app.tool()
    async def approve_finding(
        finding_id: str,
        approver_id: str,
        password: str,
        case_id: str | None = None,
        to_status: str = "APPROVED",
        from_status: str = "DRAFT",
        target_type: str = "finding",
        reason: str = "",
    ) -> dict:
        """Submit an HMAC-signed approval to the W-288 sidecar.

        MVP flow: the operator supplies the approver ``password`` as
        a parameter; the MCP server computes PBKDF2 + HMAC-SHA256
        locally and forwards the signed envelope to the sidecar. The
        password is consumed once and dropped. **WARNING:** the
        password sits in the LLM's request context for the call
        duration. Operators uneasy with that should use the Phase 2
        browser UI when it ships.

        Sidecar URL via env ``AGENTROPIX_APPROVAL_SIDECAR_URL``;
        default ``http://127.0.0.1:8800``.
        """
        result = await _inner.mcp_approve_finding(
            finding_id=finding_id,
            approver_id=approver_id,
            password=password,
            case_id=case_id,
            to_status=to_status,
            from_status=from_status,
            target_type=target_type,
            reason=reason,
        )
        return result.model_dump()

    @app.tool()
    async def retract_approval(
        approval_id: str,
        approver_id: str,
        password: str,
        reason: str,
        case_id: str | None = None,
    ) -> dict:
        """Append a compensating VOID/REVOKED entry retracting a prior approval.

        The append-only way to undo a wrong/phantom approval (e.g. an approval
        signed for a finding that never existed) — never a hard delete. Signs
        (target_type=approval, APPROVED -> REVOKED) through the same W-288 HMAC
        flow, producing a signed, chained ledger row referencing the voided
        approval_id. A non-empty ``reason`` is required (chain-of-custody).
        """
        result = await _inner.mcp_retract_approval(
            approval_id=approval_id,
            approver_id=approver_id,
            password=password,
            reason=reason,
            case_id=case_id,
        )
        return result.model_dump()

    @app.tool()
    async def report_generate(
        profile: str = "full",
        case_id: str | None = None,
    ) -> dict:
        """Build a report payload for one of 6 profiles.

        Profiles:
          * ``full``        — comprehensive IR report (exec summary
                              + findings + timeline + IOCs)
          * ``executive``   — 1-2 page management briefing (top tactics,
                              hosts, severity mix)
          * ``timeline``    — chronological narrative (APPROVED only)
          * ``ioc``         — structured IOC export with MITRE mapping
          * ``findings``    — detailed APPROVED findings
          * ``status``      — quick standup (DRAFT/APPROVED/REJECTED
                              breakdown — NOT filtered to APPROVED)

        ``report_id`` is deterministic over
        ``(case_id, profile, snapshot_at, sorted approved finding_ids)``
        so two renders at the same moment produce the same id.
        """
        result = await _inner.mcp_report_generate(profile=profile, case_id=case_id)
        return result.model_dump()

    @app.tool()
    async def report_export(
        tier: str = "analyst",
        fmt: str = "md",
        case_id: str | None = None,
    ) -> dict:
        """Render a case report tier to a file/format (ADR-024 multi-tier engine).

        Projects the canonical report sections into one audience tier and
        renders it:

          * ``tier``  — ``analyst`` (full technical) | ``executive``
                        (management briefing) | ``business`` (risk/compliance)
          * ``fmt``   — ``md`` (Markdown+Mermaid, source of truth) | ``html``
                        (self-contained, offline) | ``pdf`` (capability-gated)

        Higher tiers link back to analyst findings; a drifted/synthesized claim
        is rejected (no-drift invariant). ``pdf`` needs a local Chromium or
        WeasyPrint engine — if absent, returns a structured error with the
        install hint (nothing is installed). Returns the export result
        (``tier``, ``fmt``, ``mime``, ``path``, inline ``content`` for text).
        """
        result = await _inner.mcp_report_export(tier=tier, fmt=fmt, case_id=case_id)
        return result.model_dump()

    @app.tool()
    async def idx_ingest(
        hostname: str,
        case_id: str | None = None,
        findings: list[dict] | None = None,
        timeline_events: list[dict] | None = None,
        dry_run: bool = True,
        mutation_token: str | None = None,
    ) -> dict:
        """Structured ingest: route normalized findings + timeline
        events into ``agentropix-findings-*`` + ``agentropix-timeline-*``.

        MVP scope: this tool accepts pre-shaped finding / timeline
        dicts. Auto-discovery of artifact files on disk (Valhuntir-style
        ``idx_ingest(case_dir)`` that calls KAPE) is deferred to W-292.

        Findings flow through the W-286 draft-gate so caller-supplied
        ``approval.*`` is stripped + logged + forced to DRAFT. Timeline
        events get the same DRAFT / MCP-provenance / case_id stamping.

        Args:
            hostname: source host for these artifacts. Stamped into
                every timeline event.
            findings: normalized finding dicts.
            timeline_events: normalized event dicts.
            dry_run: when True (default), nothing is written.
            mutation_token: required when ``dry_run=False`` for the
                findings half (EvidenceGate).
        """
        result = await _inner.mcp_idx_ingest(
            hostname=hostname,
            case_id=case_id,
            findings=findings,
            timeline_events=timeline_events,
            dry_run=dry_run,
            mutation_token=mutation_token,
        )
        return result.model_dump()

    # ----------------------------------------------------------------- #
    # Windows Event Log                                                  #
    # ----------------------------------------------------------------- #
    @app.tool()
    async def get_evtx(
        target: str,
        channels: list[str] | None = None,
        event_ids: list[int] | None = None,
        max_events: int = 1000,
        timeout_seconds: float | None = None,
    ) -> dict:
        """Windows .evtx parser — Security/System/Sysmon channels with EventID filter.

        ``timeout_seconds`` defaults to ``AGENTROPIX_EVTX_TIMEOUT`` (180s,
        floor 5s, ceiling 3700s). Pass an explicit value to override per
        call; values outside ``[5, 3700]`` are clamped to the nearest bound.
        Use this when parsing large event logs (e.g. Security.evtx >200MB).
        """
        result = await _inner.mcp_get_evtx(
            target,
            channels=channels,
            event_ids=event_ids,
            max_events=max_events,
            timeout_seconds=timeout_seconds,
        )
        return result.model_dump()

    # ----------------------------------------------------------------- #
    # YARA + image metadata + carving                                    #
    # ----------------------------------------------------------------- #
    @app.tool()
    async def get_image_info(image: str) -> dict:
        """ewfinfo — E01/EWF metadata (case_number, examiner, MD5, SHA1)."""
        result = await _inner.mcp_get_image_info(image)
        return result.model_dump()

    @app.tool()
    async def scan_yara(
        target: str,
        rules: list[str],
        with_meta: bool = True,
        with_strings: bool = False,
        max_matches: int | None = None,
        timeout_seconds: float | None = None,
    ) -> dict:
        """YARA — scan target against ruleset(s). Returns typed match list.

        ``timeout_seconds`` overrides the wrapper-level subprocess timeout
        for this call only. Defaults to ``AGENTROPIX_YARA_TIMEOUT`` (300 s,
        floor 5 s, ceiling 3700 s). Per-call overrides are clamped to the
        same ``[5, 3700]`` window — raise it on a 17 GB MAIL image without
        restarting the server. SIFT-W-099.
        """
        result = await _inner.mcp_scan_yara(
            target,
            rules=rules,
            with_meta=with_meta,
            with_strings=with_strings,
            max_matches=max_matches,
            timeout_seconds=timeout_seconds,
        )
        return result.model_dump()

    @app.tool()
    async def run_bulk_extractor(
        target: str,
        out_dir: str | None = None,
        enable_scanners: list[str] | None = None,
        disable_scanners: list[str] | None = None,
        only_scanner: str | None = None,
        max_features: int = 10000,
        summary_only: bool = False,
    ) -> dict:
        """bulk_extractor 1.6.x — feature carving (emails, IPs, URLs, etc.).

        ``out_dir`` is the directory bulk_extractor writes feature files
        into. When the caller omits it (typical Claude Desktop call),
        a fresh ``/tmp/agentropix-sift-bulk-<uuid>/`` is auto-created
        under the Thymus-allowed write-zone prefix. ``summary_only=True``
        (NIST1 RUN2 ISSUE-002) omits the inline feature list — keeping
        per_recorder_counts + recorder_files — so large carves fit the
        result envelope.
        """
        if out_dir is None:
            import tempfile

            out_dir = tempfile.mkdtemp(prefix="agentropix-sift-bulk-")
        result = await _inner.mcp_run_bulk_extractor(
            target,
            out_dir=out_dir,
            enable_scanners=enable_scanners,
            disable_scanners=disable_scanners,
            only_scanner=only_scanner,
            max_features=max_features,
            summary_only=summary_only,
        )
        return result.model_dump()

    @app.tool()
    async def run_strings(
        target: str,
        min_length: int = 4,
        encoding: str = "s",
        max_results: int = 1000,
    ) -> dict:
        """GNU strings — extract printable strings."""
        result = await _inner.mcp_run_strings(
            target, min_length=min_length, encoding=encoding, max_results=max_results
        )
        return result.model_dump()

    @app.tool()
    async def analyze_maldoc(
        target: str,
        timeout: float | None = None,
    ) -> dict:
        """W-221: olevba/oleid/rtfobj maldoc analysis.

        Returns a typed report of macros, IOCs, obfuscation hints, and
        RTF embedded objects (incl. CVE-2017-11882 Equation Editor
        detection). Accepts .doc[m|x] / .xls[m|x] / .ppt[m|x] / .dotm /
        .xlam / .rtf / .ole / .bin only. Read-only.
        """
        result = await _inner.mcp_analyze_maldoc(target, timeout=timeout)
        return result.model_dump()

    @app.tool()
    async def run_hashdeep(
        target: str,
        algos: list[str] | None = None,
        recursive: bool = False,
        audit: bool = False,
        max_files: int = 10000,
    ) -> dict:
        """hashdeep / md5deep — multi-algorithm file hashing + audit mode."""
        result = await _inner.mcp_run_hashdeep(
            target, algos=algos, recursive=recursive, audit=audit, max_files=max_files
        )
        return result.model_dump()

    @app.tool()
    async def run_foremost(
        target: str,
        output_dir: str | None = None,
        config: str | None = None,
        types: list[str] | None = None,
        quick: bool = False,
        audit_only: bool = False,
        max_entries: int = 10000,
    ) -> dict:
        """foremost — file carver with audit-only mode.

        ``target`` is the image (or carve-source) path; ``output_dir``
        is where carved files / the ``audit.txt`` land. When the caller
        omits ``output_dir`` (typical Claude Desktop call), a fresh
        ``/tmp/agentropix-sift-foremost-<uuid>/`` is auto-created under
        the Thymus-allowed write-zone prefix.
        """
        if output_dir is None:
            import tempfile

            output_dir = tempfile.mkdtemp(prefix="agentropix-sift-foremost-")
        result = await _inner.mcp_run_foremost(
            target,
            output_dir=output_dir,
            config=config,
            types=types,
            quick=quick,
            audit_only=audit_only,
            max_entries=max_entries,
        )
        return result.model_dump()

    @app.tool()
    async def run_exiftool(
        target: str,
        recursive: bool = False,
        fast: bool = False,
        max_files: int = 10000,
    ) -> dict:
        """ExifTool — file metadata extraction."""
        result = await _inner.mcp_run_exiftool(
            target, recursive=recursive, fast=fast, max_files=max_files
        )
        return result.model_dump()

    # ----------------------------------------------------------------- #
    # Knowledge extraction — PDF text (W-103)                            #
    # ----------------------------------------------------------------- #
    @app.tool()
    async def pdf_extract_text(
        target: str,
        pages: str | None = None,
        max_pages: int | None = None,
        max_chars: int | None = None,
        timeout_seconds: float | None = None,
    ) -> dict:
        """W-103 — pdftotext + pdfinfo for per-page text + doc metadata.

        Converts the threat-intel corpus from "indicator extraction" to
        "knowledge extraction" — point at a vendor-CTI PDF and get
        page-precise text plus title/author/created metadata, ready to
        feed downstream NER (``extract_entities``), CVE regex
        (``cve_extract``), or FTS index (``corpus_search_index``).

        ``pages`` is a ``"1-5,12,20-"`` page-range spec; ``None`` (the
        default) extracts every page. Caps default to env:
          * ``AGENTROPIX_PDF_MAX_BYTES``    (default 200 MiB) — input
            file-size cap; oversize PDFs raise before any subprocess.
          * ``AGENTROPIX_PDF_MAX_PAGES``    (default 1000) — pages
            beyond the cap surface in the result's ``skipped_pages``.
          * ``AGENTROPIX_PDF_MAX_CHARS``    (default 200_000) — per-page
            text byte cap; truncation surfaces as ``truncated=True`` on
            the page row AND on the document rollup.
          * ``AGENTROPIX_PDF_EXTRACT_TIMEOUT`` (default 180 s, floor 5,
            ceiling 3700). Per-call ``timeout_seconds`` overrides within
            the same clamp window.

        Engine is currently always ``pdftotext`` (poppler 24.x) — pypdf
        / pdfminer fallbacks documented in
        ``docs/mcp-gap-analysis/drafts/pdf_extract_text.md`` are not
        implemented in this iteration; the schema's ``engine`` field is
        kept as a forward-compatibility hook.
        """
        result = await _inner.mcp_pdf_extract_text(
            target,
            pages=pages,
            max_pages=max_pages,
            max_chars=max_chars,
            timeout_seconds=timeout_seconds,
        )
        return result.model_dump()

    # ----------------------------------------------------------------- #
    # Path enumeration (W-084)                                           #
    # ----------------------------------------------------------------- #
    @app.tool()
    async def glob_paths(
        pattern: str,
        max_results: int = 1000,
        follow_symlinks: bool = False,
    ) -> dict:
        """Glob-based path enumeration for self-driven multi-image triage.

        Returns paths matching ``pattern`` (e.g. ``/cases/*/raw/*.E01``)
        that pass the Thymus read policy. The longest non-glob prefix of
        the pattern is policy-checked before expansion; every result is
        re-checked individually and silently dropped when outside the
        allowlist (``rejected_count`` surfaces the count).
        ``..`` traversal is rejected outright.
        """
        result = await _inner.mcp_glob_paths(
            pattern,
            max_results=max_results,
            follow_symlinks=follow_symlinks,
        )
        return result.model_dump()

    @app.tool()
    async def list_files(
        path: str,
        recursive: bool = True,
        pattern: str = "**/*",
        max_results: int | None = None,
    ) -> dict:
        """W-100 — list files under a directory (Thymus-gated convenience over ``glob_paths``).

        Operators previously abused ``run_exiftool`` / ``run_hashdeep``
        as directory listers because there was no first-class
        enumeration tool other than the glob-pattern API. This wrapper
        composes a glob from ``path`` + ``pattern`` (with ``**/``
        injected when ``recursive=True``) and delegates to the existing
        ``glob_paths`` pipeline — same Thymus read-zone enforcement,
        same symlink-drop + truncation semantics. No duplicate walking.

        ``recursive=True`` (default) walks subdirectories;
        ``recursive=False`` lists only the top-level entries of ``path``.
        ``pattern`` defaults to ``**/*`` (effectively "everything"); pass
        ``"*.evtx"`` to narrow the result-set. Any leading ``**/`` is
        stripped from ``pattern`` and re-prepended only when
        ``recursive=True`` so the same default works for both shapes.

        ``max_results`` defaults to ``AGENTROPIX_LIST_FILES_MAX_RESULTS``
        (10000, floor 1, ceiling 1_000_000). Per-call overrides are
        clamped to the same ``[1, 1_000_000]`` window.
        """
        result = await _inner.mcp_list_files(
            path,
            recursive=recursive,
            pattern=pattern,
            max_results=max_results,
        )
        return result.model_dump()

    # ----------------------------------------------------------------- #
    # W-150: Correlation layer                                           #
    # ----------------------------------------------------------------- #

    @app.tool()
    async def correlate_timeline(
        images: list[str],
        channels: list[str] | None = None,
        event_ids: list[int] | None = None,
        window_start: str | None = None,
        window_end: str | None = None,
        max_events_per_host: int = 5000,
    ) -> dict:
        """W-150 — join EVTX events from multiple hosts into a single sorted timeline.

        Fetches Security/System events from every image concurrently via
        get_evtx(), merges and sorts by UTC timestamp, and annotates each
        event with delta_ms (time since the previous event in the unified
        stream). Useful for reconstructing lateral movement sequences that
        span multiple hosts.

        images: list of evidence paths (E01 disk images or memory images).
        channels: EVTX channel filter (default: all channels).
        event_ids: EID whitelist applied after merge (default: no filter).
        window_start / window_end: ISO-8601 UTC bounds (inclusive).
        max_events_per_host: cap per get_evtx call (default: 5000).
        """
        result = await _inner.mcp_correlate_timeline(
            images,
            channels=channels,
            event_ids=event_ids,
            window_start=window_start,
            window_end=window_end,
            max_events_per_host=max_events_per_host,
        )
        return result.model_dump()

    @app.tool()
    async def build_process_tree(image: str) -> dict:
        """W-151 — build a PPID-linked process forest from a memory image.

        Calls get_pslist() (with psscan fallback on paused-VM images) and
        links processes by PPID into a rooted forest. Annotates LOLBins
        (rubyw.exe, mshta.exe, etc.) spawned by sensitive system parents
        (services.exe, lsass.exe) as suspicious.

        Returns:
          roots: well-parented process trees.
          orphans: processes whose PPID is not in the list (DKOM indicator).
          suspicious_count: number of flagged nodes.
        """
        result = await _inner.mcp_build_process_tree(image)
        return result.model_dump()

    @app.tool()
    async def pivot_on_ioc(
        ioc: str,
        images: list[str],
        artifact_types: list[str] | None = None,
        ioc_type: str = "string",
    ) -> dict:
        """W-152 — find all occurrences of an IOC across artifact types and hosts.

        Searches pslist, netscan, svcscan, and evtx results for every image
        (concurrently) for the IOC value via case-insensitive substring match.
        Returns every hit with full record context and per-host grouping.

        ioc: the value to search for — e.g. "10.10.254.1", "rubyw.exe", "spsql".
        images: evidence image paths.
        artifact_types: subset of ["pslist","netscan","svcscan","evtx"] (default: all).
        ioc_type: semantic label — "ip", "process", "service", "username", "string".
        """
        result = await _inner.mcp_pivot_on_ioc(
            ioc,
            images,
            artifact_types=artifact_types,
            ioc_type=ioc_type,
        )
        return result.model_dump()

    @app.tool()
    async def detect_sweep(
        image: str,
        window_seconds: float = 1.0,
        min_shares_per_window: int = 3,
        event_ids: list[int] | None = None,
    ) -> dict:
        """W-153 — detect SMB share enumeration bursts from EID 5140/5145 events.

        Applies a sliding-window burst detector: if >= min_shares_per_window
        unique shares are accessed from the same source IP within
        window_seconds, the burst is flagged as a lateral sweep.

        Tuned to SRL-2018 baseline where spsql accessed 20,013 shares across
        37 hosts. Default thresholds (3 shares / 1 second) catch this pattern
        with zero false positives on the SRL-2018 Security log.

        image: E01 disk image path (Security.evtx source).
        window_seconds: sliding window width in seconds (default: 1.0).
        min_shares_per_window: unique share threshold to flag (default: 3).
        event_ids: override the default {5140, 5145} filter.
        """
        result = await _inner.mcp_detect_sweep(
            image,
            window_seconds=window_seconds,
            min_shares_per_window=min_shares_per_window,
            event_ids=event_ids,
        )
        return result.model_dump()

    # ----------------------------------------------------------------- #
    # Mail forensics — header matrix (W-172)                            #
    # ----------------------------------------------------------------- #
    @app.tool()
    async def email_header_matrix(
        corpus_dir: str,
        format: str = "auto",
    ) -> dict:
        """Build a per-message header matrix for a corpus of EML/MSG files (W-172).

        Scans corpus_dir recursively for .eml / .msg files and extracts
        per-message header fields including SPF/DKIM/DMARC authentication
        results from ``Authentication-Results`` headers.

        Args:
            corpus_dir: Directory to scan (recursively).
            format: ``"eml"`` (only .eml), ``"msg"`` (only .msg),
                or ``"auto"`` (both, default).

        Returns:
            ``{"messages": [...], "summary": {...}}``
            where each message carries: path, date, from_header, from_email,
            from_display_name, reply_to, return_path, message_id, subject,
            spf, dkim, dmarc, first_received_hop.
        """
        from agentropix_mcp.wrappers.email_headers import (
            email_header_matrix as _fn,
        )

        return _fn(corpus_dir, format=format)

    # ----------------------------------------------------------------- #
    # PST/OST carve + attachment-hash IOC index (W-210)                 #
    # ----------------------------------------------------------------- #
    @app.tool()
    async def carve_pst_iocs(path: str) -> dict:
        """Carve a PST/OST file into a per-message + per-attachment IOC report (W-210).

        Capstone of the W-229 derivation chain: drives the
        ``parse_pst_with_recovery`` orchestrator (pypff + opt-in
        ``pffexport`` fallback) and emits a structured forensic
        report with:

          * ``messages`` — per-message rows tagged by the engine that
            produced them (``"pypff"`` / ``"pffexport_recovered"`` /
            ``"pffexport_recovery_failed"`` / ``"deferral"``).
          * ``iocs`` — flat per-attachment rows with SHA-256,
            filename, byte size, and back-references to the source
            message (subject + sender + date + engine + parser_note
            + source PST). Each row is a complete chain-of-custody
            record.
          * ``ioc_index`` — ``{sha256: [ioc_row, ...]}`` for O(1)
            hash-pivot queries.
          * ``summary`` — clean / recovered / failed / deferral counts,
            attachment totals, unique-hash count, PST byte size.
          * ``warnings`` — soft-error messages (PST exceeds size cap).

        Path safety: Thymus-validated + traversal-screened + symlink-
        rejected + magic-byte sniffed (``!BDN``) before any large read.

        Environment variables
        ---------------------
        * ``AGENTROPIX_PST_CARVE_MAX_BYTES`` — per-PST size cap
          (default 1 GiB, floor 4 KiB, ceiling 32 GiB). Oversize
          inputs return an empty result + a ``warnings`` entry instead
          of attempting the carve.
        * ``AGENTROPIX_MAIL_RECOVERY_ENABLED`` (SIFT-W-230) — kill
          switch for the pffexport recovery fallback. Disable values:
          ``""``/``"0"``/``"false"``/``"no"``/``"off"``.
        * ``AGENTROPIX_PFF_RECOVERY_TIMEOUT`` — pffexport subprocess
          timeout in seconds (default 300, floor 30, ceiling 1800).
        * ``AGENTROPIX_PFF_RECOVERY_BIN`` — pffexport binary path
          (default ``pffexport``).
        * ``AGENTROPIX_PFF_RECOVERY_TMPDIR`` (SIFT-W-231) — staging
          dir for pffexport extraction. Default uses the system
          tempdir; set to a case-folder volume to keep attachment
          bytes contained per forensic SOP.
        * ``AGENTROPIX_PFF_RECOVERY_MAX_MESSAGES`` — cap on recovered
          message count (default 10_000, floor 100, ceiling 100_000).

        Args:
            path: Absolute path to a ``.pst`` or ``.ost`` file.

        Returns:
            See ``carve_pst_iocs`` in ``mcp_server/wrappers/pst_carve.py``
            for the full dict shape.
        """
        # PST parsing is CPU-bound + reads up to 1 GiB into memory and
        # may spawn a long-running `pffexport` subprocess. Run on a
        # worker thread so the FastMCP event loop stays responsive for
        # health probes and other concurrent tool invocations.
        import asyncio

        from agentropix_mcp.wrappers.pst_carve import (
            carve_pst_iocs as _fn,
        )

        return await asyncio.to_thread(_fn, path)

    # ----------------------------------------------------------------- #
    # GPT partition table parser (W-170)                                 #
    # ----------------------------------------------------------------- #
    @app.tool()
    async def parse_gpt(image_path: str) -> dict:
        """Parse the GPT (GUID Partition Table) of a disk image (W-170).

        Returns disk GUID, per-partition Type GUID, Unique GUID, partition
        name (UTF-16LE decoded), attribute flags, and LBA extents.  Works
        on raw disk images (.dd / .img) and EWF/E01 containers (mounted
        transparently via ewfmount).

        Args:
            image_path: Absolute path to a raw disk image or E01 container.

        Returns:
            ``{"header": {...}, "partitions": [...], "image_path": ...,
              "is_ewf": bool, "raw_stdout_sha256": ...}``
            where header carries disk_guid, total_sectors, sector_size_bytes,
            table_max_entries, first_usable_lba, last_usable_lba and each
            partition entry carries index, first_lba, last_lba, size_human,
            type_code, type_guid, type_guid_description, unique_guid,
            attribute_flags, name.
        """
        from agentropix_mcp.wrappers.gpt_parser import (
            parse_gpt as _fn,
        )

        return await _fn(image_path)

    # ----------------------------------------------------------------- #
    # Dynamic-disk container unwrapper (W-171)                          #
    # ----------------------------------------------------------------- #
    @app.tool()
    async def unwrap_disk_container(
        input_path: str,
        output_dir: str | None = None,
    ) -> dict:
        """Convert a virtual-disk container to raw format for SIFT analysis (W-171).

        Accepts VHD (legacy .vhd), VHDX (Hyper-V v2), VMDK (VMware),
        VDI (VirtualBox), and QCOW2 (KVM/QEMU) containers. Uses
        ``qemu-img convert -O raw`` and returns a SHA-256 hash of the
        raw output for chain-of-custody.

        Args:
            input_path: Absolute path to the disk container.
            output_dir: Directory to write the raw image into. Defaults
                to a fresh ``/tmp/agentropix_unwrap_*/`` temp directory.

        Returns:
            ``{"format_detected": str, "raw_image_path": str,
              "raw_image_sha256": str, "virtual_size_bytes": int,
              "actual_size_bytes": int, "is_sparse": bool,
              "metadata": dict}``
            or ``{"error": str}`` if the format is unsupported or
            conversion fails.
        """
        from agentropix_mcp.wrappers.disk_container import (
            unwrap_disk_container as _fn,
        )

        return await _fn(input_path, output_dir=output_dir)

    # ----------------------------------------------------------------- #
    # Live threat intelligence lookups (W-118)                          #
    # ----------------------------------------------------------------- #
    @app.tool()
    async def threat_intel_lookup(
        indicator: str,
        indicator_type: str | None = None,
        providers: list[str] | None = None,
        timeout: float | None = None,
    ) -> dict:
        """Look up an IOC against live threat intelligence providers (W-118).

        EGRESS-GATED: requires AGENTROPIX_ALLOW_EGRESS=1.  Without it the
        tool responds immediately with egress_allowed=False; no network call
        is made.

        Args:
            indicator: MD5 / SHA1 / SHA256 hash, IPv4 address, or domain
                name.  URLs, emails, and whitespace-containing strings are
                rejected.
            indicator_type: Explicit type override.  Inferred automatically
                when omitted.  Values: "md5", "sha1", "sha256", "ip",
                "domain".
            providers: Subset of {"virustotal", "otx"}.  Defaults to all
                providers enabled via AGENTROPIX_TI_PROVIDERS.
            timeout: Per-call HTTP timeout in seconds (30-300; default 60).

        Returns:
            ThreatIntelReport dict: {indicator, indicator_type,
            providers_queried, results, aggregate_verdict, tool,
            egress_allowed, raw_stdout_sha256}.
        """
        from agentropix_mcp.wrappers.threat_intel import (
            threat_intel_lookup as _fn,
        )

        return await _fn(
            indicator,
            indicator_type=indicator_type,
            providers=providers,
            timeout=timeout,
        )

    # ----------------------------------------------------------------- #
    # Wazuh IOC push tools (Step 1 — W-A01/W-A03)                       #
    # ----------------------------------------------------------------- #
    try:
        from agentropix_mcp.wrappers.wazuh_tools import register_wazuh_tools

        register_wazuh_tools(app)
        logger.info(
            "Wazuh IOC push tools registered (wazuh_publish_iocs, "
            "wazuh_hunt_ioc, wazuh_vuln_query, wazuh_index_findings)"
        )
    except Exception as _wazuh_exc:  # pragma: no cover
        logger.warning("Wazuh tools not registered: %s", _wazuh_exc)

    # ----------------------------------------------------------------- #
    # Wazuh intel-membership tool (tool-A, 2026-05-11 4-tools eval)     #
    # ----------------------------------------------------------------- #
    try:
        from agentropix_mcp.wrappers.wazuh_intel import register_wazuh_intel_tools

        register_wazuh_intel_tools(app)
        logger.info("Wazuh intel-check tool registered (wazuh_check_intel)")
    except Exception as _wazuh_intel_exc:  # pragma: no cover
        logger.warning("Wazuh intel tool not registered: %s", _wazuh_intel_exc)

    # Phase 1 fix: Add bearer token authentication middleware to HTTP transport
    _add_auth_middleware(app)
    return app


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:  # noqa: F821
    """Parse CLI args for the FastMCP entry point.

    Defaults preserve M8.4a behaviour: ``--transport stdio`` runs an MCP
    stdio server (paired with ``mcp.json`` ``"command"`` entries). The
    ``--transport http`` variant (M8.6, ADR-017) binds an HTTP+SSE
    listener intended for **Tailscale-only** exposure — the operator
    looks up their tailnet IP via ``tailscale ip -4`` and passes it as
    ``--host``. Public binding (``0.0.0.0``) is intentionally NOT a
    default; the operator must opt in explicitly with ``--public``,
    which logs a loud warning and is intended for hardened deploys
    only (Path 2 in the M8 sprint plan).
    """
    import argparse

    parser = argparse.ArgumentParser(
        prog="agentropix-sift-mcp",
        description="Agentropix-SIFT FastMCP server (37 forensic + analysis + health tools).",
    )
    parser.add_argument(
        "--transport",
        choices=("stdio", "http"),
        default="stdio",
        help="MCP transport. stdio (default) for local Claude Desktop "
        "command-based mcp.json; http for Tailscale-only or hardened "
        "remote exposure.",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="HTTP bind address (transport=http only). Defaults to "
        "127.0.0.1; supply your Tailscale IP (e.g. `tailscale ip -4`) "
        "to expose on the tailnet, or use --public to bind 0.0.0.0.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="HTTP port (transport=http only). Default 8765.",
    )
    parser.add_argument(
        "--public",
        action="store_true",
        help="Bind 0.0.0.0 (ALL interfaces, public-facing). Off by default "
        "and strongly discouraged without bearer-token auth + evidence "
        "Thymus tightening (see docs/adr/ADR-017-tailnet-mcp-exposure.md).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    """Entry point — runs the FastMCP server on the chosen transport."""
    _configure_logging()
    args = parse_args(argv)
    app = _build_app()

    # W-088/W-089: surface every AGENTROPIX_* tunable + the resolved
    # Thymus allowed-prefix list so operators see the active runtime
    # configuration without grepping the source. Logged once, BEFORE
    # ``app.run()`` so the banner is the first server-state line.
    log_active_configuration(logger)
    _check_dependencies()

    if args.transport == "stdio":
        logger.info("Agentropix-SIFT FastMCP server starting on stdio (38 tools registered)")
        app.run()  # blocks; speaks MCP protocol over stdin/stdout
        return

    # transport == "http" — Tailscale-or-localhost path (ADR-017).
    if args.public:
        host = "0.0.0.0"
        logger.warning(
            "FastMCP binding to 0.0.0.0 (PUBLIC). Ensure bearer auth "
            "+ Thymus is locked to samples/ before exposing. See "
            "docs/adr/ADR-017-tailnet-mcp-exposure.md."
        )
    elif args.host:
        host = args.host
    else:
        host = "127.0.0.1"
        logger.info(
            "No --host supplied; binding loopback only. To expose on "
            "your tailnet, run `tailscale ip -4` and pass it via --host."
        )

    logger.info(
        "Agentropix-SIFT FastMCP server starting on http://%s:%d/sse (38 tools registered)",
        host,
        args.port,
    )
    # FastMCP's HTTP transport speaks MCP over SSE under /sse; clients
    # add it to mcp.json as `{"url": "http://<host>:<port>/sse"}`.
    app.run(transport="http", host=host, port=args.port)


if __name__ == "__main__":
    main()
