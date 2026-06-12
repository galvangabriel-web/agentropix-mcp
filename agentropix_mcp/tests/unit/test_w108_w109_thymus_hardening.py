"""W-108 / W-109 — Thymus hardening: encoded traversal + path length guard.

Both gaps were surfaced by hardtest-20260428T1849Z Test B (adversarial
inputs).

W-108 — `%2e%2e` (URL-encoded `..`) bypassed the FORBIDDEN_PATTERNS
screen because the screen ran on the raw path BEFORE URL-decoding. After
decoding, `os.path.normpath` collapsed `..` away entirely, so the
post-canonicalize check also missed it. Fix: re-screen FORBIDDEN_PATTERNS
against the URL-decoded form, BEFORE normpath, inside `_canonicalize`.

W-109 — Paths longer than PATH_MAX (4096 bytes) silently got ALLOW from
Thymus, then raised an untyped `OSError: ENAMETOOLONG` inside the wrapper.
Fix: reject any input where `len(path) > 4096` with a typed
`REJECT_PATH_TOO_LONG`.
"""

from __future__ import annotations

import pytest

from agentropix_mcp.thymus_policy import (
    ThymusEvidencePolicy,
    _PATH_MAX_BYTES,
)


@pytest.fixture
def policy() -> ThymusEvidencePolicy:
    return ThymusEvidencePolicy()


class TestW108EncodedTraversal:
    """`%2e%2e` URL-encoded `..` must be detected after URL-decode."""

    def test_lowercase_encoded_traversal_rejected(
        self, policy: ThymusEvidencePolicy
    ) -> None:
        result = policy.check_read("/cases/srl-2018/%2e%2e/etc")
        assert result is not None
        assert "forbidden pattern in URL-decoded path" in result
        assert ".." in result

    def test_uppercase_encoded_traversal_rejected(
        self, policy: ThymusEvidencePolicy
    ) -> None:
        """`%2E%2E` (uppercase hex) must also be caught — `urllib.unquote`
        is case-insensitive about hex digits."""
        result = policy.check_read("/cases/srl-2018/%2E%2E/etc/shadow")
        assert result is not None
        assert "forbidden pattern" in result

    def test_mixed_case_encoded_traversal_rejected(
        self, policy: ThymusEvidencePolicy
    ) -> None:
        result = policy.check_read("/cases/srl-2018/%2e%2E/etc")
        assert result is not None
        assert "forbidden pattern" in result

    def test_double_encoded_traversal_rejected(
        self, policy: ThymusEvidencePolicy
    ) -> None:
        """Single-pass URL-decode catches `%2e%2e`. Double-encoded
        `%252e%252e` decodes to `%2e%2e` after one pass — that string
        does NOT contain `..`, so it passes both screens. Then normpath
        cannot collapse it, and the prefix check decides. Result: stays
        under `/cases/`, gets ALLOW. Documented behavior — single-pass
        decode is the contract."""
        # This test pins the deliberate single-pass behavior so a future
        # change to multi-pass decoding doesn't accidentally introduce
        # a different attack surface.
        result = policy.check_read("/cases/srl-2018/%252e%252e/etc")
        # Single-pass decode → '%2e%2e' (literal), still under /cases/ → ALLOW
        assert result is None

    def test_raw_dotdot_still_rejected(
        self, policy: ThymusEvidencePolicy
    ) -> None:
        """Sanity check: the original raw `..` screen still works."""
        result = policy.check_read("/cases/srl-2018/../etc")
        assert result is not None
        assert "forbidden pattern '..'" in result

    def test_legitimate_percent_encoding_still_works(
        self, policy: ThymusEvidencePolicy
    ) -> None:
        """`%20` (space) is a legitimate URL-encoding — must NOT trigger
        the W-108 re-screen since space is not in FORBIDDEN_PATTERNS."""
        # Path doesn't exist, but the W-108 check runs on the
        # URL-decoded form before existence is consulted, and must NOT
        # flag this as a forbidden pattern.
        result = policy.check_read("/cases/srl-2018/foo%20bar.E01")
        # The W-108 screen does not fire (space is not forbidden); the
        # path may still REJECT for not existing, but it must NOT be
        # rejected for "forbidden pattern".
        if result is not None:
            assert "forbidden pattern" not in result


class TestW109PathLengthGuard:
    """Paths longer than PATH_MAX must be rejected with a typed reason."""

    def test_path_at_limit_allowed(self, policy: ThymusEvidencePolicy) -> None:
        """Exactly PATH_MAX bytes is allowed (boundary case)."""
        # Build a path that's exactly PATH_MAX bytes long, under /cases/.
        prefix = "/cases/srl-2018/"
        filler = "a" * (_PATH_MAX_BYTES - len(prefix) - len(".E01"))
        path = prefix + filler + ".E01"
        assert len(path) == _PATH_MAX_BYTES
        result = policy.check_read(path)
        # The W-109 length guard does NOT fire at the limit. Path may
        # still REJECT for not existing, but the reason must NOT be
        # PATH_TOO_LONG.
        if result is not None:
            assert "REJECT_PATH_TOO_LONG" not in result

    def test_path_one_over_limit_rejected(
        self, policy: ThymusEvidencePolicy
    ) -> None:
        path = "/cases/srl-2018/" + "a" * (_PATH_MAX_BYTES + 1) + ".E01"
        assert len(path) > _PATH_MAX_BYTES
        result = policy.check_read(path)
        assert result is not None
        assert "REJECT_PATH_TOO_LONG" in result

    def test_8000_char_path_rejected(self, policy: ThymusEvidencePolicy) -> None:
        """Original B7 adversarial case from hardtest."""
        long_path = "/cases/srl-2018/" + "a" * 8000 + ".E01"
        result = policy.check_read(long_path)
        assert result is not None
        assert "REJECT_PATH_TOO_LONG" in result

    def test_pathmax_constant_matches_linux(self) -> None:
        """Ensure the constant tracks Linux PATH_MAX."""
        assert _PATH_MAX_BYTES == 4096

    def test_path_too_long_runs_before_other_checks(
        self, policy: ThymusEvidencePolicy
    ) -> None:
        """The length guard must fire FIRST so a multi-MB malicious path
        doesn't waste cycles in URL-decode or normpath."""
        # 100KB path with traversal + null byte — length guard wins.
        evil = "/cases/" + ("../" * 30000) + "\x00"
        result = policy.check_read(evil)
        assert result is not None
        assert "REJECT_PATH_TOO_LONG" in result


class TestNoRegression:
    """All adversarial cases from hardtest Test B that previously passed
    must keep passing after the W-108/W-109 fixes."""

    def test_null_byte_still_rejected(self, policy: ThymusEvidencePolicy) -> None:
        result = policy.check_read("/cases/srl-2018/\x00etc/passwd")
        assert result is not None
        assert "NUL byte" in result

    def test_proc_still_rejected(self, policy: ThymusEvidencePolicy) -> None:
        result = policy.check_read("/proc/1/mem")
        assert result is not None
        assert "/proc/" in result

    def test_etc_shadow_still_rejected(self, policy: ThymusEvidencePolicy) -> None:
        result = policy.check_read("/etc/shadow")
        assert result is not None
        assert "REJECT_OUTSIDE_ALLOWLIST" in result

    def test_double_slash_still_normalized(
        self, policy: ThymusEvidencePolicy
    ) -> None:
        """W-097 normalization must still collapse `//` correctly."""
        result = policy.check_read("/cases/srl-2018/base-dc-cdrive.E01")
        result2 = policy.check_read("//cases/srl-2018/base-dc-cdrive.E01")
        # Both should reach the same decision — neither rejected (file
        # exists under allowed prefix in the test environment).
        assert (result is None) == (result2 is None)
