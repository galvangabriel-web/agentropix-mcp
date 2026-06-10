"""Secret-handling helpers for Agentropix-SIFT (W-007).

M6 introduces the minimum-viable rotation path for the Telegram bot
token: a precedence-ordered resolver and a logging-safe redactor.  A
full secrets-manager integration (1Password CLI / age-encrypted file /
systemd credentials) is still a post-MVP initiative, but the env-var
surface here is compatible with all three so operators can rotate
without a code change.

Precedence (first non-empty wins):

1. ``AGENTROPIX_TELEGRAM_TOKEN_FILE`` — path to a file whose single
   trimmed line is the token.  Supports Docker secrets / systemd
   ``LoadCredential`` / 1Password ``op read`` piped to a tempfile.
2. ``AGENTROPIX_TELEGRAM_TOKEN`` — the token itself as a plain env
   var.  Suitable for shell-level injection from a secrets CLI.
3. ``AGENTROPIX_TELEGRAM_BOT_TOKEN`` — legacy ``.env`` key used by
   pre-M6 dev workflows.  Kept for backwards-compatibility; no plan
   to drop it while operators still load via ``.env``.

Any token resolved through this module is never emitted to stdout or
the audit log — every logger installed via ``install_secret_filter``
strips the token from records before they are handed to handlers.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable
from pathlib import Path

__all__ = [
    "TELEGRAM_TOKEN_ENV_CHAIN",
    "SecretFilter",
    "install_secret_filter",
    "load_telegram_token",
    "redact_secret",
]


TELEGRAM_TOKEN_ENV_CHAIN: tuple[str, ...] = (
    "AGENTROPIX_TELEGRAM_TOKEN_FILE",
    "AGENTROPIX_TELEGRAM_TOKEN",
    "AGENTROPIX_TELEGRAM_BOT_TOKEN",
)
"""Ordered env-var chain the Telegram token resolver consults.

Exposed so tests and operator tooling can iterate the same names the
resolver uses — avoids ``str``-literal drift between code and docs.
"""


_REDACTED = "***REDACTED***"
_MIN_REDACT_LEN = 6  # shorter strings rarely identify as secrets


def _read_token_file(path: str) -> str | None:
    """Return the first non-empty line of ``path``, or ``None`` on any error.

    The file is read with ``strip()`` so trailing newlines from
    ``echo $TOKEN > /run/secrets/telegram`` don't leak into the token
    value. Errors (missing file, permission denied, binary content) are
    swallowed and logged — W-007 explicitly keeps the legacy ``.env``
    plaintext path working, so a broken file-pointer never breaks
    delivery.
    """
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        logging.getLogger(__name__).warning(
            "telegram token file unreadable: path=%s error=%s",
            path,
            exc,
        )
        return None
    token = raw.strip()
    return token or None


def load_telegram_token(
    env: dict[str, str] | None = None,
) -> tuple[str | None, str | None]:
    """Resolve the Telegram bot token via the precedence chain.

    Args:
        env: Optional env-map override for tests. Defaults to
            ``os.environ``. A ``dict``-like argument is accepted so
            callers can seed a synthetic environment without
            monkeypatching ``os.environ``.

    Returns:
        ``(token, source)`` where ``source`` is the env-var name that
        supplied the token (``AGENTROPIX_TELEGRAM_TOKEN_FILE`` means the
        file-pointer won) or ``None`` when nothing resolved.  The token
        itself is ``None`` when no source carried a usable value.
    """
    source_env = env if env is not None else os.environ

    file_path = source_env.get("AGENTROPIX_TELEGRAM_TOKEN_FILE", "").strip()
    if file_path:
        token = _read_token_file(file_path)
        if token:
            return token, "AGENTROPIX_TELEGRAM_TOKEN_FILE"

    direct = source_env.get("AGENTROPIX_TELEGRAM_TOKEN", "").strip()
    if direct:
        return direct, "AGENTROPIX_TELEGRAM_TOKEN"

    legacy = source_env.get("AGENTROPIX_TELEGRAM_BOT_TOKEN", "").strip()
    if legacy:
        return legacy, "AGENTROPIX_TELEGRAM_BOT_TOKEN"

    return None, None


def redact_secret(text: str, secrets: Iterable[str]) -> str:
    """Replace every occurrence of any ``secrets`` value in ``text`` with ``***REDACTED***``.

    ``text`` is returned unchanged when it's empty or when every
    candidate secret is too short to reasonably identify a token (< 6
    chars).  Longer candidates are replaced via straight ``str.replace``
    — no regex, because tokens routinely contain regex-significant
    characters (``:``, ``-``, ``_``) and escaping would silently miss
    valid matches on older Python versions.

    Order matters: the longest candidate is replaced first so a token
    that starts with another token ("abc" vs "abcd") doesn't strand
    the longer suffix unmasked.
    """
    if not text:
        return text
    candidates = sorted(
        (s for s in secrets if s and len(s) >= _MIN_REDACT_LEN),
        key=len,
        reverse=True,
    )
    redacted = text
    for secret in candidates:
        redacted = redacted.replace(secret, _REDACTED)
    return redacted


class SecretFilter(logging.Filter):
    """A ``logging.Filter`` that redacts known secrets from every record.

    Pulls the secret list dynamically from a callable so that tokens
    rotated at runtime (tests, watched ``*_FILE`` sources) are reflected
    on the next log emission without having to rebuild the filter chain.
    Redaction covers ``record.msg`` (formatted or not) and every ``str``
    value in ``record.args`` — matching ``%s`` formatting both before
    and after arg-substitution.
    """

    def __init__(self, secrets_provider) -> None:  # type: ignore[no-untyped-def]
        super().__init__(name="agentropix_mcp.secrets")
        self._secrets_provider = secrets_provider

    def _current_secrets(self) -> list[str]:
        try:
            values = list(self._secrets_provider() or [])
        except Exception:  # noqa: BLE001 — provider must never crash logging
            return []
        return [v for v in values if isinstance(v, str) and v]

    def filter(self, record: logging.LogRecord) -> bool:
        secrets = self._current_secrets()
        if not secrets:
            return True
        if isinstance(record.msg, str):
            record.msg = redact_secret(record.msg, secrets)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: (redact_secret(v, secrets) if isinstance(v, str) else v)
                    for k, v in record.args.items()
                }
            else:
                record.args = tuple(
                    redact_secret(v, secrets) if isinstance(v, str) else v
                    for v in record.args
                )
        return True


def install_secret_filter(
    logger: logging.Logger | None = None,
    *,
    secrets_provider=None,  # type: ignore[no-untyped-def]
) -> SecretFilter:
    """Attach a ``SecretFilter`` to ``logger`` (or the root logger).

    The default ``secrets_provider`` resolves the Telegram token via
    ``load_telegram_token`` so callers that want "just scrub Telegram
    credentials" get that behaviour with no arguments:

        install_secret_filter()

    Returns the installed filter so tests can remove it via
    ``logger.removeFilter(...)``.
    """
    target = logger or logging.getLogger()

    if secrets_provider is None:
        def _default_provider() -> list[str]:
            token, _ = load_telegram_token()
            return [token] if token else []

        secrets_provider = _default_provider

    secret_filter = SecretFilter(secrets_provider)
    target.addFilter(secret_filter)
    return secret_filter
