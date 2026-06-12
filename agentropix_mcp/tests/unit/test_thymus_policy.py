"""Unit tests for Thymus Evidence Policy (S-02: 0 evidence writes)."""

import os
import tempfile

import pytest

from agentropix_mcp.thymus_policy import ThymusEvidencePolicy


class TestThymusReadPolicy:
    """Thymus must allow reads from evidence zones and reject everything else."""

    def setup_method(self) -> None:
        self.policy = ThymusEvidencePolicy()

    def test_allow_cases_path(self) -> None:
        assert self.policy.check_read("/cases/evidence.dd") is None

    def test_allow_mnt_path(self) -> None:
        assert self.policy.check_read("/mnt/forensic/image.raw") is None

    def test_allow_media_path(self) -> None:
        assert self.policy.check_read("/media/usb/dump.mem") is None

    def test_allow_evidence_path(self) -> None:
        assert self.policy.check_read("/evidence/case001/disk.dd") is None

    def test_reject_home_path(self) -> None:
        result = self.policy.check_read("/home/user/secrets.txt")
        assert result is not None
        assert "REJECT" in result

    def test_reject_etc_path(self) -> None:
        result = self.policy.check_read("/etc/passwd")
        assert result is not None
        assert "REJECT" in result

    def test_reject_path_traversal(self) -> None:
        result = self.policy.check_read("/cases/../etc/passwd")
        assert result is not None
        assert "forbidden pattern" in result

    def test_reject_dev_path(self) -> None:
        result = self.policy.check_read("/dev/sda")
        assert result is not None
        assert "forbidden pattern" in result

    def test_reject_proc_path(self) -> None:
        result = self.policy.check_read("/proc/1/mem")
        assert result is not None
        assert "forbidden pattern" in result


class TestThymusWritePolicy:
    """All writes must be rejected — evidence integrity is architectural."""

    def setup_method(self) -> None:
        self.policy = ThymusEvidencePolicy()

    def test_reject_write_to_cases(self) -> None:
        result = self.policy.check_write("/cases/evidence.dd")
        assert "REJECT" in result
        assert "ALL writes" in result

    def test_reject_write_to_any_path(self) -> None:
        result = self.policy.check_write("/tmp/output.txt")
        assert "REJECT" in result


class TestThymusAuditLog:
    """Thymus must log all decisions for S-06 trace capture."""

    def setup_method(self) -> None:
        self.policy = ThymusEvidencePolicy()

    def test_audit_log_populated_on_allow(self) -> None:
        self.policy.check_read("/cases/test.dd")
        assert len(self.policy.audit_log) == 1
        assert self.policy.audit_log[0]["action"] == "ALLOW"

    def test_audit_log_populated_on_reject(self) -> None:
        self.policy.check_read("/home/user/file.txt")
        assert len(self.policy.audit_log) == 1
        assert self.policy.audit_log[0]["action"] == "REJECT"

    def test_audit_log_has_timestamp(self) -> None:
        self.policy.check_read("/cases/test.dd")
        assert "timestamp" in self.policy.audit_log[0]

    def test_extra_allowed_paths(self) -> None:
        policy = ThymusEvidencePolicy(extra_allowed=["/custom/evidence/"])
        assert policy.check_read("/custom/evidence/disk.dd") is None


class TestThymusWriteRejectionAudit:
    """Write rejections must be logged for audit trail."""

    def setup_method(self) -> None:
        self.policy = ThymusEvidencePolicy()

    def test_write_rejection_logged(self) -> None:
        self.policy.check_write("/cases/evidence.dd")
        assert len(self.policy.audit_log) == 1
        assert self.policy.audit_log[0]["action"] == "REJECT_WRITE"


# ===================================================================
# Phase 2: Symlink validation tests
# ===================================================================


class TestThymusSymlinkValidation:
    """Symlink attacks must be blocked by Thymus policy."""

    def setup_method(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="agentropix-sift-test-")
        self.evidence_dir = os.path.join(self.tmpdir, "evidence") + "/"
        os.makedirs(self.evidence_dir, exist_ok=True)
        self.real_file = os.path.join(self.evidence_dir, "disk.dd")
        open(self.real_file, "w").close()
        self.policy = ThymusEvidencePolicy(
            extra_allowed=[self.evidence_dir], auto_detect=False
        )

    def teardown_method(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_real_file_allowed(self) -> None:
        assert self.policy.check_read(self.real_file) is None

    def test_symlink_to_etc_shadow_rejected(self) -> None:
        link = os.path.join(self.evidence_dir, "shadow.dd")
        os.symlink("/etc/shadow", link)
        result = self.policy.check_read(link)
        assert result is not None
        assert "REJECT" in result

    def test_symlink_to_proc_rejected(self) -> None:
        link = os.path.join(self.evidence_dir, "proc.dd")
        os.symlink("/proc/self/environ", link)
        result = self.policy.check_read(link)
        assert result is not None
        assert "REJECT" in result
        assert "/proc/" in result

    def test_symlink_to_dev_rejected(self) -> None:
        link = os.path.join(self.evidence_dir, "dev.raw")
        os.symlink("/dev/sda", link)
        result = self.policy.check_read(link)
        assert result is not None
        assert "REJECT" in result
        assert "/dev/" in result

    def test_chained_symlink_rejected(self) -> None:
        intermediate = os.path.join(self.tmpdir, "hop")
        os.symlink("/etc/passwd", intermediate)
        link = os.path.join(self.evidence_dir, "chained.dd")
        os.symlink(intermediate, link)
        result = self.policy.check_read(link)
        assert result is not None
        assert "REJECT" in result

    def test_relative_traversal_symlink_rejected(self) -> None:
        link = os.path.join(self.evidence_dir, "traversal.dd")
        os.symlink("../../../../../../etc/passwd", link)
        result = self.policy.check_read(link)
        assert result is not None
        assert "REJECT" in result

    def test_good_symlink_within_zone_allowed(self) -> None:
        link = os.path.join(self.evidence_dir, "alias.dd")
        os.symlink(self.real_file, link)
        assert self.policy.check_read(link) is None

    def test_symlink_audit_logged(self) -> None:
        link = os.path.join(self.evidence_dir, "logged.dd")
        os.symlink(self.real_file, link)
        self.policy.check_read(link)
        symlink_entries = [e for e in self.policy.audit_log if e["action"] == "SYMLINK"]
        assert len(symlink_entries) == 1

    def test_permission_error_no_crash(self) -> None:
        """Restricted paths must not crash the policy engine."""
        result = self.policy.check_read("/root/.ssh/id_rsa")
        assert result is not None
        assert "REJECT" in result


# ===================================================================
# Phase 2: Auto-detection tests
# ===================================================================


class TestThymusAutoDetection:
    """Auto-detection adds evidence parent directories to allowed list."""

    def test_e01_auto_detected(self) -> None:
        tmpdir = tempfile.mkdtemp(prefix="agentropix-sift-test-")
        img = os.path.join(tmpdir, "evidence.e01")
        open(img, "w").close()
        policy = ThymusEvidencePolicy()
        result = policy.check_read(img)
        assert result is None
        import shutil
        shutil.rmtree(tmpdir)

    def test_mem_auto_detected(self) -> None:
        tmpdir = tempfile.mkdtemp(prefix="agentropix-sift-test-")
        img = os.path.join(tmpdir, "memory.mem")
        open(img, "w").close()
        policy = ThymusEvidencePolicy()
        result = policy.check_read(img)
        assert result is None
        import shutil
        shutil.rmtree(tmpdir)

    def test_dd_auto_detected(self) -> None:
        tmpdir = tempfile.mkdtemp(prefix="agentropix-sift-test-")
        img = os.path.join(tmpdir, "disk.dd")
        open(img, "w").close()
        policy = ThymusEvidencePolicy()
        result = policy.check_read(img)
        assert result is None
        import shutil
        shutil.rmtree(tmpdir)

    def test_non_evidence_not_auto_detected(self) -> None:
        tmpdir = tempfile.mkdtemp()
        txt = os.path.join(tmpdir, "readme.txt")
        open(txt, "w").close()
        policy = ThymusEvidencePolicy()
        result = policy.check_read(txt)
        assert result is not None
        import shutil
        shutil.rmtree(tmpdir)

    def test_auto_detect_disabled(self) -> None:
        tmpdir = tempfile.mkdtemp()
        img = os.path.join(tmpdir, "evidence.e01")
        open(img, "w").close()
        policy = ThymusEvidencePolicy(auto_detect=False)
        result = policy.check_read(img)
        assert result is not None
        import shutil
        shutil.rmtree(tmpdir)

    def test_auto_detect_logs_auto_allow(self) -> None:
        tmpdir = tempfile.mkdtemp(prefix="agentropix-sift-test-")
        img = os.path.join(tmpdir, "evidence.e01")
        open(img, "w").close()
        policy = ThymusEvidencePolicy()
        policy.check_read(img)
        auto_entries = [e for e in policy.audit_log if e["action"] == "AUTO_ALLOW"]
        assert len(auto_entries) == 1
        import shutil
        shutil.rmtree(tmpdir)

    def test_auto_detect_no_duplicate_prefix(self) -> None:
        tmpdir = tempfile.mkdtemp(prefix="agentropix-sift-test-")
        img1 = os.path.join(tmpdir, "disk1.e01")
        img2 = os.path.join(tmpdir, "disk2.e01")
        open(img1, "w").close()
        open(img2, "w").close()
        policy = ThymusEvidencePolicy()
        policy.check_read(img1)
        policy.check_read(img2)
        auto_entries = [e for e in policy.audit_log if e["action"] == "AUTO_ALLOW"]
        assert len(auto_entries) == 1  # second call should not add duplicate
        import shutil
        shutil.rmtree(tmpdir)


class TestEnvVarAllowedPrefixes:
    """Bug 2 fix (2026-04-25) — AGENTROPIX_THYMUS_ALLOWED_PREFIXES is now
    actually wired into the policy constructor. The runbook documented
    this env var for guest-onboarding ("tighten Thymus to a per-case
    directory") but the previous implementation never read it.

    These tests lock the contract that the env var:
      - is honored at policy-construction time;
      - accepts comma- AND colon-separated lists;
      - normalizes each entry to end with "/" so prefix matching is
        unambiguous;
      - works correctly with paths containing spaces (the trigger
        case: SRL-2018 case dir at
        ``~/project/Compromised APT Attack Scenarios/...``);
      - applies uniformly across file extensions (a non-evidence-image
        like ``.zip`` or ``.txt`` in an allow-listed dir still passes).
    """

    @staticmethod
    def _case_dir() -> str:
        return (
            "~/project/Compromised APT Attack Scenarios/"
            "SRL-2018-Compromised Enterprise Network"
        )

    def test_env_var_unset_yields_default_allowlist(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("AGENTROPIX_THYMUS_ALLOWED_PREFIXES", raising=False)
        policy = ThymusEvidencePolicy()
        # Default static allowlist only.
        assert policy._allowed_prefixes == [
            "/cases/",
            "/mnt/",
            "/media/",
            "/evidence/",
            "/tmp/agentropix-sift-",
            "/usr/share/yara/rules/",
            "/usr/share/yara-rules/",
        ]

    def test_env_var_single_prefix_with_spaces(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        case = self._case_dir()
        monkeypatch.setenv("AGENTROPIX_THYMUS_ALLOWED_PREFIXES", case)
        policy = ThymusEvidencePolicy()
        # Trailing slash auto-appended.
        assert case + "/" in policy._allowed_prefixes

    def test_env_var_consistent_across_file_extensions(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Bug 2 root cause: the operator added a per-case dir, expected
        every artifact in it to be readable, but only ``.e01`` / ``.dmp``
        files passed because auto-allow was the only effective path. This
        test locks that the env-var-supplied prefix lets ANY extension
        through."""
        case = self._case_dir()
        monkeypatch.setenv("AGENTROPIX_THYMUS_ALLOWED_PREFIXES", case)
        policy = ThymusEvidencePolicy()
        for name in (
            "memory.dmp",
            "evidence.zip",
            "forensic-bundle.7z",
            "notes.txt",
            "subdir/extracted.bin",
        ):
            verdict = policy.check_read(f"{case}/{name}")
            assert verdict is None, f"expected PASS for {name}, got {verdict!r}"

    def test_env_var_comma_separated(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(
            "AGENTROPIX_THYMUS_ALLOWED_PREFIXES",
            "/srv/case-a/, /srv/case-b/",
        )
        policy = ThymusEvidencePolicy()
        assert "/srv/case-a/" in policy._allowed_prefixes
        assert "/srv/case-b/" in policy._allowed_prefixes
        assert policy.check_read("/srv/case-a/foo.zip") is None
        assert policy.check_read("/srv/case-b/bar.txt") is None

    def test_env_var_colon_separated_unix_pathlike(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Operators familiar with $PATH conventions may use ``:`` —
        accepted as long as the env var doesn't simultaneously contain
        a comma."""
        monkeypatch.setenv(
            "AGENTROPIX_THYMUS_ALLOWED_PREFIXES",
            "/srv/case-a/:/srv/case-b/",
        )
        policy = ThymusEvidencePolicy()
        assert "/srv/case-a/" in policy._allowed_prefixes
        assert "/srv/case-b/" in policy._allowed_prefixes

    def test_env_var_traversal_still_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Adding a per-case prefix must not weaken the FORBIDDEN_PATTERNS
        check. Path traversal still gets stopped before any prefix match
        is considered."""
        case = self._case_dir()
        monkeypatch.setenv("AGENTROPIX_THYMUS_ALLOWED_PREFIXES", case)
        policy = ThymusEvidencePolicy()
        verdict = policy.check_read(f"{case}/../etc/passwd")
        assert verdict is not None
        assert "forbidden pattern" in verdict.lower()

    def test_env_var_empty_entries_dropped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(
            "AGENTROPIX_THYMUS_ALLOWED_PREFIXES",
            ", /case-a/, , /case-b/, ",
        )
        policy = ThymusEvidencePolicy()
        assert "/case-a/" in policy._allowed_prefixes
        assert "/case-b/" in policy._allowed_prefixes
        # No empty/whitespace entries leak through.
        assert "" not in policy._allowed_prefixes
        assert "/" not in policy._allowed_prefixes

    def test_env_var_extra_allowed_kwarg_combined(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``extra_allowed`` kwarg + env var both contribute; neither
        clobbers the other."""
        monkeypatch.setenv("AGENTROPIX_THYMUS_ALLOWED_PREFIXES", "/srv/from-env/")
        policy = ThymusEvidencePolicy(extra_allowed=["/srv/from-kwarg/"])
        assert "/srv/from-env/" in policy._allowed_prefixes
        assert "/srv/from-kwarg/" in policy._allowed_prefixes


class TestThymusAllowedDirectoryItself:
    """Regression for SIFT-W-078 (2026-04-25): the allowed directory
    itself, passed as ``target`` (e.g. ``run_exiftool`` recursing on the
    case-dir root), was rejected because ``Path.resolve()`` strips the
    trailing slash while every prefix is normalized to end with ``/``.
    Files INSIDE the directory always worked; the directory root did
    not. The fix accepts ``resolved + '/' == prefix`` as an exact match
    and must NOT widen to siblings (``/Net2`` should still not match
    ``/Net/``)."""

    def test_static_default_dir_allowed_with_trailing_slash(self) -> None:
        policy = ThymusEvidencePolicy()
        assert policy.check_read("/cases/") is None

    def test_static_default_dir_allowed_without_trailing_slash(self) -> None:
        policy = ThymusEvidencePolicy()
        assert policy.check_read("/cases") is None

    def test_extra_allowed_dir_itself_with_trailing_slash(self) -> None:
        policy = ThymusEvidencePolicy(
            extra_allowed=["/srv/case-a/"], auto_detect=False
        )
        assert policy.check_read("/srv/case-a/") is None

    def test_extra_allowed_dir_itself_without_trailing_slash(self) -> None:
        policy = ThymusEvidencePolicy(
            extra_allowed=["/srv/case-a/"], auto_detect=False
        )
        assert policy.check_read("/srv/case-a") is None

    def test_env_var_dir_with_spaces_itself_allowed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        case = (
            "~/project/Compromised APT Attack Scenarios/"
            "SRL-2018-Compromised Enterprise Network"
        )
        monkeypatch.setenv("AGENTROPIX_THYMUS_ALLOWED_PREFIXES", case)
        policy = ThymusEvidencePolicy(auto_detect=False)
        assert policy.check_read(case) is None
        assert policy.check_read(case + "/") is None

    def test_sibling_directory_still_rejected(self) -> None:
        """Tightness check: ``/srv/case-a-evil`` must not pass just
        because ``/srv/case-a/`` is allowed. The ``+ '/' ==`` form
        compares equality, not prefix, so this is structurally safe —
        but lock it with a test."""
        policy = ThymusEvidencePolicy(
            extra_allowed=["/srv/case-a/"], auto_detect=False
        )
        assert policy.check_read("/srv/case-a-evil") is not None
        assert policy.check_read("/srv/case-a-evil/file.txt") is not None

    def test_sibling_prefix_lookalike_still_rejected(self) -> None:
        """``/cases2/`` shares 6 chars with ``/cases/`` but is a
        different directory; must remain rejected when auto-detect is
        off. (auto-detect would widen this via the .dd extension; that
        behavior is locked by TestThymusAutoDetection and is orthogonal
        to the trailing-slash fix.)"""
        policy = ThymusEvidencePolicy(auto_detect=False)
        assert policy.check_read("/cases2") is not None
        assert policy.check_read("/cases2/") is not None
        assert policy.check_read("/cases2/file.dd") is not None


class TestThymusYaraToolingZone:
    """Regression for SIFT-W-080 (2026-04-25): ``scan_yara`` calls
    against the standard SIFT-shipped YARA rule directories
    (``/usr/share/yara/rules/``, ``/usr/share/yara-rules/``) tripped
    Thymus because those paths weren't in the default allow-list. They
    are now defaults — root-owned, immutable to the agent, included so
    a stock SIFT install needs no env-var override on every deploy."""

    def test_yara_rules_path_allowed(self) -> None:
        policy = ThymusEvidencePolicy(auto_detect=False)
        assert policy.check_read("/usr/share/yara/rules/cobalt-strike.yar") is None
        assert policy.check_read("/usr/share/yara/rules/subdir/x.yar") is None

    def test_yara_dash_rules_path_allowed(self) -> None:
        policy = ThymusEvidencePolicy(auto_detect=False)
        assert policy.check_read("/usr/share/yara-rules/index.yar") is None
        assert policy.check_read("/usr/share/yara-rules/malware/mimikatz.yar") is None

    def test_yara_rules_dir_itself_allowed(self) -> None:
        """Combine SIFT-W-078 (directory-itself match) with W-080: when
        an agent passes ``/usr/share/yara/rules/`` as the rules
        argument expecting recursive scan, Thymus must accept."""
        policy = ThymusEvidencePolicy(auto_detect=False)
        assert policy.check_read("/usr/share/yara/rules/") is None
        assert policy.check_read("/usr/share/yara/rules") is None
        assert policy.check_read("/usr/share/yara-rules/") is None

    def test_yara_sibling_paths_still_rejected(self) -> None:
        """Tightness: ``/usr/share/yara-rules-evil/`` must not pass."""
        policy = ThymusEvidencePolicy(auto_detect=False)
        assert policy.check_read("/usr/share/yara-rules-evil/x.yar") is not None
        assert policy.check_read("/usr/share/yara/rulesets/x.yar") is not None

    def test_other_usr_share_paths_still_rejected(self) -> None:
        """Widening to YARA tooling must not leak to /usr/share/ at
        large — agents should not be able to read e.g.
        ``/usr/share/doc/`` or ``/usr/share/keyrings/``."""
        policy = ThymusEvidencePolicy(auto_detect=False)
        assert policy.check_read("/usr/share/doc/something") is not None
        assert policy.check_read("/usr/share/keyrings/anything") is not None
        assert policy.check_read("/usr/share/ca-certificates/cert") is not None


class TestThymusRejectReasonCodes:
    """W-087 (2026-04-26): REJECT messages now carry disambiguated
    reason codes so operators can tell whether a denial was caused by
    (a) path outside allowlist, (b) path doesn't exist, or (c) symlink
    target outside allowlist — without grepping the policy source."""

    def test_reject_outside_allowlist_emits_specific_code(self) -> None:
        """An existing on-disk path outside any allowed prefix must
        emit ``REJECT_OUTSIDE_ALLOWLIST`` (not the generic message)."""
        policy = ThymusEvidencePolicy(auto_detect=False)
        result = policy.check_read("/etc/passwd")
        assert result is not None
        assert "REJECT_OUTSIDE_ALLOWLIST" in result

    def test_reject_nonexistent_path_emits_specific_code(self) -> None:
        """A path under an allowed-looking prefix that doesn't exist on
        disk must emit ``REJECT_PATH_NOT_FOUND``. Note: the path must
        also be outside the allowlist for the rejection branch to
        fire — we use ``/nonexistent-root-xyz/`` which is not allowed
        and definitionally not on disk."""
        policy = ThymusEvidencePolicy(auto_detect=False)
        result = policy.check_read("/nonexistent-root-xyz/missing.dd")
        assert result is not None
        assert "REJECT_PATH_NOT_FOUND" in result

    def test_reject_symlink_emits_specific_code(self, tmp_path) -> None:
        """A symlink in an allowed evidence dir whose target lives
        outside the allowlist must emit
        ``REJECT_SYMLINK_TARGET_OUTSIDE_ALLOWLIST``."""
        evidence_dir = str(tmp_path) + "/"
        link = os.path.join(evidence_dir, "evil.dd")
        os.symlink("/etc/passwd", link)
        policy = ThymusEvidencePolicy(
            extra_allowed=[evidence_dir], auto_detect=False
        )
        result = policy.check_read(link)
        assert result is not None
        assert "REJECT_SYMLINK_TARGET_OUTSIDE_ALLOWLIST" in result


class TestW091AuditLogRingBuffer:
    """W-091 — ``_audit_log`` must be a bounded deque, not an unbounded list.

    On reject-storm load (Phase D.1: 8 sessions x 1000 rejects x N
    triages over an 8 h endurance window), an unbounded list would
    accrue ~250 bytes per entry indefinitely, eating Phase E's "RSS
    growth <= 50 MB over 8 h" gate before a real leak is visible.
    """

    def test_audit_log_default_cap_is_1000(self) -> None:
        policy = ThymusEvidencePolicy()
        assert policy._audit_log.maxlen == 1000

    def test_audit_log_env_override_clamped_to_floor(self, monkeypatch) -> None:
        monkeypatch.setenv("AGENTROPIX_THYMUS_AUDIT_LOG_RING_SIZE", "10")
        policy = ThymusEvidencePolicy()
        assert policy._audit_log.maxlen == 100

    def test_audit_log_env_override_clamped_to_ceiling(self, monkeypatch) -> None:
        monkeypatch.setenv("AGENTROPIX_THYMUS_AUDIT_LOG_RING_SIZE", "999999999")
        policy = ThymusEvidencePolicy()
        assert policy._audit_log.maxlen == 100_000

    def test_audit_log_env_override_within_bounds(self, monkeypatch) -> None:
        monkeypatch.setenv("AGENTROPIX_THYMUS_AUDIT_LOG_RING_SIZE", "5000")
        policy = ThymusEvidencePolicy()
        assert policy._audit_log.maxlen == 5000

    def test_audit_log_drops_oldest_entries_when_full(self, monkeypatch) -> None:
        """Eviction is FIFO so most-recent decisions stay visible."""
        monkeypatch.setenv("AGENTROPIX_THYMUS_AUDIT_LOG_RING_SIZE", "100")
        policy = ThymusEvidencePolicy()
        # Generate 250 rejects (denied paths). 100 maxlen means the
        # first 150 get evicted; the last 100 survive.
        for i in range(250):
            policy.check_read(f"/etc/probe-{i:04d}")
        snapshot = policy.audit_log
        assert len(snapshot) == 100
        # Most-recent reject is the last one fired.
        last_reason_path = snapshot[-1]["path"]
        assert "/etc/probe-0249" in last_reason_path
        # First surviving entry is probe-0150 (probes 0..149 were
        # evicted to make room).
        first_reason_path = snapshot[0]["path"]
        assert "/etc/probe-0150" in first_reason_path

    def test_audit_log_property_returns_list_snapshot(self) -> None:
        """``audit_log`` returns a list copy so callers cannot mutate state."""
        policy = ThymusEvidencePolicy()
        policy.check_read("/etc/passwd")  # one reject
        snapshot = policy.audit_log
        assert isinstance(snapshot, list)
        assert len(snapshot) == 1
        snapshot.clear()
        # Mutation of the returned list does not affect the policy.
        assert len(policy.audit_log) == 1
