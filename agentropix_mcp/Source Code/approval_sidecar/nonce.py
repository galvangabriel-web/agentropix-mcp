"""SIFT-W-288: in-memory TTL nonce store.

Defeats replay attacks across the challenge-response: the sidecar
issues a nonce on ``/challenge`` and remembers it for ``ttl_seconds``
(default 60). The client must HMAC-sign the nonce and submit it back
within the window; the sidecar's ``consume()`` is single-use, so a
replayed approval is rejected immediately.

In-memory is fine for Phase 1 — the sidecar is single-process and
single-examiner (operator decision 2026-05-27). Multi-examiner or
HA deployments would swap in a Redis-backed store via the same
``NonceStore`` protocol; the routes never see the implementation.

Thread/concurrency story:

  - The sidecar runs under uvicorn's asyncio event loop in a single
    thread, so the store dict is accessed serially from the
    perspective of any single request. No locking required.
  - GC is opportunistic on every ``issue()`` and ``consume()`` —
    expired entries are dropped lazily. This bounds memory at
    O(requests_per_TTL_window). At 60 s default + 100 r/s the upper
    bound is ~6 000 entries (~600 KB), fully acceptable.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass


class NonceUnknown(Exception):
    """Raised when ``consume(nonce)`` is called with a nonce the store
    never issued (or has GC'd)."""


class NonceExpired(Exception):
    """Raised when ``consume(nonce)`` is called after the TTL window
    has closed for that nonce."""


@dataclass(frozen=True)
class _Entry:
    issued_at: float  # monotonic seconds
    examiner_id: str
    target_id: str


class NonceStore:
    """Single-use, time-bounded nonce store.

    Args:
        ttl_seconds: how long an issued nonce remains valid. 60 s is
            the default. Operators can tighten with
            ``AGENTROPIX_APPROVAL_SIDECAR_NONCE_TTL`` (read in
            ``config.SidecarConfig.from_env``).
        clock: monotonic-clock provider for tests.
    """

    def __init__(
        self,
        ttl_seconds: float = 60.0,
        clock=time.monotonic,  # type: ignore[assignment]
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")
        self._ttl = float(ttl_seconds)
        self._clock = clock
        self._store: dict[str, _Entry] = {}

    # --- public API --------------------------------------------------- #

    def issue(self, examiner_id: str, target_id: str) -> str:
        """Issue a fresh nonce bound to a specific (examiner, target).

        Binding both fields means a nonce issued for "approve F-001 as
        alice" cannot be replayed to "approve F-002 as alice" — the
        signed message in the approve flow includes target_id, so the
        HMAC check will fail.
        """
        self._gc()
        nonce = secrets.token_urlsafe(24)  # 192 bits, JSON-safe
        self._store[nonce] = _Entry(
            issued_at=self._clock(),
            examiner_id=examiner_id,
            target_id=target_id,
        )
        return nonce

    def consume(self, nonce: str, *, examiner_id: str, target_id: str) -> None:
        """Single-use consume. Raises if the nonce was never issued
        for this (examiner, target) pair, or if it has expired.

        Always removes the nonce from the store, even on failure —
        a wrong-target consume is itself a replay attempt and the
        nonce should not survive it.
        """
        entry = self._store.pop(nonce, None)
        if entry is None:
            raise NonceUnknown(f"nonce not found: {nonce[:8]}...")
        age = self._clock() - entry.issued_at
        if age > self._ttl:
            raise NonceExpired(f"nonce expired (age={age:.1f}s > ttl={self._ttl:.1f}s)")
        if entry.examiner_id != examiner_id:
            raise NonceUnknown("nonce was issued for a different examiner")
        if entry.target_id != target_id:
            raise NonceUnknown("nonce was issued for a different target")

    # --- maintenance -------------------------------------------------- #

    def _gc(self) -> None:
        """Drop entries older than TTL. Opportunistic — runs on every
        ``issue()`` so a steady stream of issuance keeps memory bounded."""
        now = self._clock()
        expired = [n for n, e in self._store.items() if now - e.issued_at > self._ttl]
        for n in expired:
            self._store.pop(n, None)

    def __len__(self) -> int:
        return len(self._store)
