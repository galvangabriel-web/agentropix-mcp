"""Configuration loader — reads settings from file or env vars."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

_SEARCH_PATHS = [
    Path(os.environ.get("AGENTROPIX_CONFIG", "")),
    Path("/etc/agentropix-sift/config.json"),
    Path.home() / ".config" / "agentropix-sift" / "config.json",
]

_DEFAULTS = {
    "thymus_policy": {
        "allowed_paths": ["/cases/", "/mnt/", "/media/", "/evidence/", "/tmp/agentropix-sift-"],
        "forbidden_patterns": ["..", "~", "/dev/", "/proc/", "/sys/"],
        "auto_detect": True,
    },
    "tools": {
        "plaso": {"timeout_cap": 600, "min_disk_mb": 500},
        "volatility": {"timeout": 120},
    },
    "monitoring": {
        "mem_limit_mb": 0,
        "rate_limit": 60,
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Deep merge override into base (override wins)."""
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config() -> dict:
    """Load configuration from first available config file, merged with defaults.

    The search order is: ``$AGENTROPIX_CONFIG`` → ``/etc/...`` → ``~/.config/...``.
    Tests may monkeypatch ``_SEARCH_PATHS`` directly to override the search
    list (the module attribute is the documented seam).
    """
    for path in _SEARCH_PATHS:
        if path and path.is_file():
            try:
                with open(path) as f:
                    user_config = json.load(f)
                logger.info("Loaded config from %s", path)
                return _deep_merge(_DEFAULTS, user_config)
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("Failed to load config from %s: %s", path, e)

    logger.debug("No config file found, using defaults")
    return dict(_DEFAULTS)


# --------------------------------------------------------------------------- #
# Lazy singleton — for callers that bypass the CLI (MCP server, library use).
# CLI calls ``load_config()`` directly and threads the result via Blackboard.
# --------------------------------------------------------------------------- #

_cached_config: dict | None = None


def get_config() -> dict:
    """Return the process-wide config dict (memoised on first call).

    Reads the file once and caches the merged dict so wrappers and tests
    that import without going through the CLI see the same view. Use
    ``reset_config_cache()`` in tests that need a fresh load.
    """
    global _cached_config
    if _cached_config is None:
        _cached_config = load_config()
    return _cached_config


def reset_config_cache() -> None:
    """Drop the memoised config — tests use this to re-read from disk/env."""
    global _cached_config
    _cached_config = None
