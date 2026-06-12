"""Chaos / fault-injection tests for critical resilience paths.

Each test exercises a failure mode that was historically a crash or silent
bad-data path. These tests must NOT be mocked at the wrong level — the
goal is to verify that the *cleanup* and *error-propagation* paths that
were written to fix real production bugs (W-022, W-041, and the extract
traversal guard) actually execute.

Tests use real tmpdir fixtures and synthetic subprocesses (AsyncMock) so
they run on any host without requiring the actual SIFT tools to be installed.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytestmark = pytest.mark.chaos


# ---------------------------------------------------------------------------
# Test 1 — W-022: Plaso tmpdir is cleaned even if SIGKILL leaves files behind
# ---------------------------------------------------------------------------


class TestPlasoCleanupOnTimeout:
    """W-022 regression: shutil.rmtree(ignore_errors=True) in finally cleans up."""

    @pytest.mark.asyncio
    async def test_tmpdir_removed_after_timeout(self, tmp_path: Path) -> None:
        """Plaso wrapper removes its tmpdir even when TimeoutError fires."""
        from agentropix_mcp.wrappers.plaso import get_timeline

        fake_proc = MagicMock()
        fake_proc.pid = 99999
        fake_proc.returncode = None
        fake_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
        fake_proc.wait = AsyncMock(return_value=None)
        fake_proc.kill = MagicMock()

        captured_tmpdirs: list[str] = []
        real_mkdtemp = tempfile.mkdtemp

        def _tracking_mkdtemp(**kwargs):
            d = real_mkdtemp(**kwargs)
            captured_tmpdirs.append(d)
            # Simulate a lingering worker file in the tmpdir
            Path(d, "worker_artifact.tmp").write_bytes(b"x" * 1024)
            return d

        with (
            patch("agentropix_mcp.wrappers.plaso.tempfile.mkdtemp", side_effect=_tracking_mkdtemp),
            patch("asyncio.create_subprocess_exec", return_value=fake_proc),
            patch("os.killpg", return_value=None),
            patch("shutil.which", return_value="/usr/bin/log2timeline.py"),
        ):
            image = tmp_path / "sample.dd"
            image.write_bytes(b"\x00" * 512)

            with pytest.raises((TimeoutError, asyncio.TimeoutError)):
                await get_timeline(image, timeout=0.001)

        for d in captured_tmpdirs:
            assert not Path(d).exists(), f"tmpdir {d} was NOT cleaned up after timeout"

    @pytest.mark.asyncio
    async def test_tmpdir_removed_on_success(self, tmp_path: Path) -> None:
        """Plaso wrapper removes its tmpdir on success (no leak on happy path)."""
        from agentropix_mcp.wrappers.plaso import get_timeline

        fake_proc = MagicMock()
        fake_proc.pid = 11111
        fake_proc.returncode = 0
        fake_proc.communicate = AsyncMock(return_value=(b"", b""))
        fake_proc.wait = AsyncMock(return_value=None)

        captured_tmpdirs: list[str] = []
        real_mkdtemp = tempfile.mkdtemp

        def _tracking_mkdtemp(**kwargs):
            d = real_mkdtemp(**kwargs)
            captured_tmpdirs.append(d)
            return d

        with (
            patch("agentropix_mcp.wrappers.plaso.tempfile.mkdtemp", side_effect=_tracking_mkdtemp),
            patch("asyncio.create_subprocess_exec", return_value=fake_proc),
            patch("shutil.which", return_value="/usr/bin/log2timeline.py"),
        ):
            image = tmp_path / "sample.dd"
            image.write_bytes(b"\x00" * 512)
            await get_timeline(image, timeout=30.0)

        for d in captured_tmpdirs:
            assert not Path(d).exists(), f"tmpdir {d} leaked on success"


# ---------------------------------------------------------------------------
# Test 2 — W-041: bulk_extractor EWF auto-mount and no-ewfmount fallback
# ---------------------------------------------------------------------------


class TestBulkExtractorEwfHandling:
    """W-041: EWF targets are mounted via ewfmount; missing ewfmount raises clearly."""

    @pytest.mark.asyncio
    async def test_ewf_target_raises_clearly_when_ewfmount_missing(self, tmp_path: Path) -> None:
        """When ewfmount is absent, raise RuntimeError with remediation hint."""
        from agentropix_mcp.wrappers.bulk_extractor import run_bulk_extractor

        image = tmp_path / "evidence.E01"
        image.write_bytes(b"EVF\x09\x0d\x0a\xff\x00" + b"\x00" * 512)
        out = tmp_path / "be_out"

        def _which(name: str) -> str | None:
            if name == "ewfmount":
                return None
            if name == "bulk_extractor":
                return "/usr/bin/bulk_extractor"
            return None

        with patch("shutil.which", side_effect=_which):
            with pytest.raises(RuntimeError, match="ewf.*libewf|libewf.*ewf|ewfmount"):
                await run_bulk_extractor(image, out)

    @pytest.mark.asyncio
    async def test_ewf_target_mounts_and_passes_ewf1_to_be(self, tmp_path: Path) -> None:
        """When ewfmount is present, BE receives the mounted ewf1 path (not the .E01)."""
        from agentropix_mcp.wrappers.bulk_extractor import run_bulk_extractor

        image = tmp_path / "evidence.E01"
        image.write_bytes(b"EVF\x09\x0d\x0a\xff\x00" + b"\x00" * 512)
        out = tmp_path / "be_out"
        out.mkdir()

        received_cmd: list[list[str]] = []

        fake_be_proc = MagicMock()
        fake_be_proc.returncode = 0
        fake_be_proc.communicate = AsyncMock(return_value=(b"", b""))
        fake_be_proc.kill = MagicMock()

        fake_mount_proc = MagicMock()
        fake_mount_proc.returncode = 0
        fake_mount_proc.communicate = AsyncMock(return_value=(b"", b""))

        fake_umount_proc = MagicMock()
        fake_umount_proc.returncode = 0
        fake_umount_proc.communicate = AsyncMock(return_value=(b"", b""))

        mount_dir_holder: list[Path] = []

        async def _fake_subprocess(*args, **kwargs):
            cmd = list(args)
            received_cmd.append(cmd)
            tool = cmd[0] if cmd else ""
            if "ewfmount" in tool:
                mnt = Path(cmd[-1])
                mount_dir_holder.append(mnt)
                # Simulate ewf1 appearing in mount dir
                (mnt / "ewf1").write_bytes(b"\x00" * 512)
                return fake_mount_proc
            if "fusermount" in tool:
                return fake_umount_proc
            return fake_be_proc

        def _which(name: str) -> str | None:
            mapping = {
                "ewfmount": "/usr/bin/ewfmount",
                "bulk_extractor": "/usr/bin/bulk_extractor",
                "fusermount": "/usr/bin/fusermount",
            }
            return mapping.get(name)

        with (
            patch("asyncio.create_subprocess_exec", side_effect=_fake_subprocess),
            patch("shutil.which", side_effect=_which),
        ):
            await run_bulk_extractor(image, out, zap=True, timeout=30.0)

        be_invocations = [c for c in received_cmd if c and "bulk_extractor" in c[0]]
        assert be_invocations, "bulk_extractor was never called"
        be_target = be_invocations[0][-1]
        assert "ewf1" in be_target, f"BE should receive ewf1 path, got: {be_target}"
        assert str(image) not in be_target, "BE must NOT receive the raw .E01 path"

    @pytest.mark.asyncio
    async def test_ewf_mountdir_cleaned_after_be_failure(self, tmp_path: Path) -> None:
        """ewfmount tmpdir is removed even when BE raises RuntimeError."""
        from agentropix_mcp.wrappers.bulk_extractor import run_bulk_extractor

        image = tmp_path / "evidence.E01"
        image.write_bytes(b"EVF\x09\x0d\x0a\xff\x00" + b"\x00" * 512)
        out = tmp_path / "be_out"

        fake_mount_proc = MagicMock()
        fake_mount_proc.returncode = 0
        fake_mount_proc.communicate = AsyncMock(return_value=(b"", b""))

        fake_be_proc = MagicMock()
        fake_be_proc.returncode = 1
        fake_be_proc.communicate = AsyncMock(return_value=(b"", b"bulk_extractor error"))
        fake_be_proc.kill = MagicMock()

        fake_umount_proc = MagicMock()
        fake_umount_proc.returncode = 0
        fake_umount_proc.communicate = AsyncMock(return_value=(b"", b""))

        created_tmpdirs: list[str] = []
        real_mkdtemp = tempfile.mkdtemp

        def _tracking_mkdtemp(**kwargs):
            d = real_mkdtemp(**kwargs)
            created_tmpdirs.append(d)
            return d

        async def _fake_subprocess(*args, **kwargs):
            cmd = list(args)
            if "ewfmount" in (cmd[0] if cmd else ""):
                mnt = Path(cmd[-1])
                (mnt / "ewf1").write_bytes(b"\x00" * 32)
                return fake_mount_proc
            if "fusermount" in (cmd[0] if cmd else ""):
                return fake_umount_proc
            return fake_be_proc

        def _which(name: str) -> str | None:
            return {
                "ewfmount": "/usr/bin/ewfmount",
                "bulk_extractor": "/usr/bin/bulk_extractor",
                "fusermount": "/usr/bin/fusermount",
            }.get(name)

        with (
            patch("asyncio.create_subprocess_exec", side_effect=_fake_subprocess),
            patch("shutil.which", side_effect=_which),
            patch(
                "agentropix_mcp.wrappers.bulk_extractor.tempfile.mkdtemp",
                side_effect=_tracking_mkdtemp,
            ),
        ):
            with pytest.raises(RuntimeError):
                await run_bulk_extractor(image, out, timeout=30.0)

        for d in created_tmpdirs:
            assert not Path(d).exists(), f"EWF mount tmpdir {d} leaked after BE failure"


# ---------------------------------------------------------------------------
# Test 3 — extract_files: path traversal is rejected before any subprocess
# ---------------------------------------------------------------------------


class TestExtractFilesTraversalRejected:
    """Verify that in-container paths with traversal/invalid segments land in rejected[]
    before any subprocess is invoked, and never appear in the extracted manifest."""

    @pytest.mark.asyncio
    async def test_dotdot_path_lands_in_rejected(self, tmp_path: Path) -> None:
        """A path containing ``..`` appears in manifest.rejected, not manifest.extracted."""
        from agentropix_mcp.wrappers.extract import extract_files

        image = tmp_path / "disk.dd"
        image.write_bytes(b"\x00" * 512)
        dest = tmp_path / "out"
        dest.mkdir()

        # No subprocess should fire — icat/ifind are not patched, but the path
        # is rejected at normalisation time so no exec attempt is made.
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            manifest = await extract_files(image, ["../../etc/passwd"], dest)

        assert "../../etc/passwd" in manifest.rejected, (
            "traversal path should be in manifest.rejected"
        )
        assert len(manifest.extracted) == 0
        mock_exec.assert_not_called()

    @pytest.mark.asyncio
    async def test_nul_byte_path_lands_in_rejected(self, tmp_path: Path) -> None:
        """A path containing a NUL byte is rejected before any subprocess invocation."""
        from agentropix_mcp.wrappers.extract import extract_files

        image = tmp_path / "disk.dd"
        image.write_bytes(b"\x00" * 512)
        dest = tmp_path / "out"
        dest.mkdir()

        bad_path = "Windows/System32\x00/config/SOFTWARE"
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            manifest = await extract_files(image, [bad_path], dest)

        assert bad_path in manifest.rejected
        assert len(manifest.extracted) == 0
        mock_exec.assert_not_called()

    @pytest.mark.asyncio
    async def test_valid_path_not_rejected(self, tmp_path: Path) -> None:
        """A clean in-container path is NOT placed in rejected (subprocess may still fail)."""
        from agentropix_mcp.wrappers.extract import extract_files

        image = tmp_path / "disk.dd"
        image.write_bytes(b"\x00" * 512)
        dest = tmp_path / "out"
        dest.mkdir()

        fake_ifind = MagicMock()
        fake_ifind.returncode = 1  # ifind can't find it → path goes to missing
        fake_ifind.communicate = AsyncMock(return_value=(b"", b"not found"))

        with patch("asyncio.create_subprocess_exec", return_value=fake_ifind):
            manifest = await extract_files(
                image, ["Windows/System32/config/SOFTWARE"], dest
            )

        assert "Windows/System32/config/SOFTWARE" not in manifest.rejected, (
            "valid path must not be pre-rejected"
        )


# ---------------------------------------------------------------------------
# Test 4 — R1: ewfmount succeeds (rc=0) but ewf1 never appears → RuntimeError
# ---------------------------------------------------------------------------


class TestEwfMountMissingEwf1:
    """R1: ewfmount exits 0 but ewf1 is absent — raise and clean up tmpdir."""

    @pytest.mark.asyncio
    async def test_ewf_mount_fails_when_ewf1_absent(self, tmp_path: Path) -> None:
        """RuntimeError is raised and the mount tmpdir is removed when ewf1 missing."""
        from agentropix_mcp.wrappers.bulk_extractor import run_bulk_extractor

        image = tmp_path / "evidence.E01"
        image.write_bytes(b"EVF\x09\x0d\x0a\xff\x00" + b"\x00" * 512)
        out = tmp_path / "be_out"

        created_tmpdirs: list[str] = []
        real_mkdtemp = tempfile.mkdtemp

        def _tracking_mkdtemp(**kwargs):
            d = real_mkdtemp(**kwargs)
            created_tmpdirs.append(d)
            return d  # do NOT create ewf1 — simulate missing device

        fake_mount_proc = MagicMock()
        fake_mount_proc.returncode = 0
        fake_mount_proc.communicate = AsyncMock(return_value=(b"", b""))

        fake_umount_proc = MagicMock()
        fake_umount_proc.returncode = 0
        fake_umount_proc.communicate = AsyncMock(return_value=(b"", b""))

        async def _fake_subprocess(*args, **kwargs):
            cmd = list(args)
            if "ewfmount" in (cmd[0] if cmd else ""):
                # ewfmount exits 0 but does NOT create ewf1
                return fake_mount_proc
            if "fusermount" in (cmd[0] if cmd else ""):
                return fake_umount_proc
            raise AssertionError("bulk_extractor should never be called")

        def _which(name: str) -> str | None:
            return {
                "ewfmount": "/usr/bin/ewfmount",
                "bulk_extractor": "/usr/bin/bulk_extractor",
                "fusermount": "/usr/bin/fusermount",
            }.get(name)

        with (
            patch("asyncio.create_subprocess_exec", side_effect=_fake_subprocess),
            patch("shutil.which", side_effect=_which),
            patch(
                "agentropix_mcp.wrappers.bulk_extractor.tempfile.mkdtemp",
                side_effect=_tracking_mkdtemp,
            ),
        ):
            with pytest.raises(RuntimeError, match="ewf1"):
                await run_bulk_extractor(image, out, timeout=30.0)

        for d in created_tmpdirs:
            assert not Path(d).exists(), f"mount tmpdir {d} leaked after missing-ewf1 error"


# ---------------------------------------------------------------------------
# Test 5 — R2: os.killpg raises ProcessLookupError → TimeoutError propagates
# ---------------------------------------------------------------------------


class TestPlasoKillpgFailure:
    """R2: os.killpg raises ProcessLookupError (process already dead) — no crash."""

    @pytest.mark.asyncio
    async def test_plaso_killpg_failure_is_swallowed(self, tmp_path: Path) -> None:
        """ProcessLookupError from os.killpg is swallowed; TimeoutError still raises."""
        from agentropix_mcp.wrappers.plaso import get_timeline

        fake_proc = MagicMock()
        fake_proc.pid = 99998
        fake_proc.returncode = None
        fake_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
        fake_proc.wait = AsyncMock(return_value=None)
        fake_proc.kill = MagicMock()

        captured_tmpdirs: list[str] = []
        real_mkdtemp = tempfile.mkdtemp

        def _tracking_mkdtemp(**kwargs):
            d = real_mkdtemp(**kwargs)
            captured_tmpdirs.append(d)
            return d

        with (
            patch("agentropix_mcp.wrappers.plaso.tempfile.mkdtemp", side_effect=_tracking_mkdtemp),
            patch("asyncio.create_subprocess_exec", return_value=fake_proc),
            # Simulate race: process already dead when we try to killpg
            patch("os.killpg", side_effect=ProcessLookupError("no such process")),
            patch("shutil.which", return_value="/usr/bin/log2timeline.py"),
        ):
            image = tmp_path / "memory.lime"
            image.write_bytes(b"\x00" * 512)

            with pytest.raises((TimeoutError, asyncio.TimeoutError)):
                await get_timeline(image, timeout=0.001)

        for d in captured_tmpdirs:
            assert not Path(d).exists(), f"plaso tmpdir {d} leaked after killpg failure"


# ---------------------------------------------------------------------------
# Test 6 — R3: fusermount exits non-zero → tmpdir still removed
# ---------------------------------------------------------------------------


class TestFusermountNonZeroCleanup:
    """R3: fusermount rc=1 (stale mount, already gone) must not prevent tmpdir removal."""

    @pytest.mark.asyncio
    async def test_fusermount_nonzero_still_cleans_tmpdir(self, tmp_path: Path) -> None:
        """BE tmpdir is removed even when fusermount exits with rc=1."""
        from agentropix_mcp.wrappers.bulk_extractor import run_bulk_extractor

        image = tmp_path / "evidence.E01"
        image.write_bytes(b"EVF\x09\x0d\x0a\xff\x00" + b"\x00" * 512)
        out = tmp_path / "be_out"

        created_tmpdirs: list[str] = []
        real_mkdtemp = tempfile.mkdtemp

        def _tracking_mkdtemp(**kwargs):
            d = real_mkdtemp(**kwargs)
            created_tmpdirs.append(d)
            return d

        fake_mount_proc = MagicMock()
        fake_mount_proc.returncode = 0
        fake_mount_proc.communicate = AsyncMock(return_value=(b"", b""))

        fake_be_proc = MagicMock()
        fake_be_proc.returncode = 0
        fake_be_proc.communicate = AsyncMock(return_value=(b"", b""))

        fake_umount_proc = MagicMock()
        fake_umount_proc.returncode = 1  # stale / already unmounted
        fake_umount_proc.communicate = AsyncMock(return_value=(b"", b"device is busy"))

        async def _fake_subprocess(*args, **kwargs):
            cmd = list(args)
            tool = cmd[0] if cmd else ""
            if "ewfmount" in tool:
                mnt = Path(cmd[-1])
                (mnt / "ewf1").write_bytes(b"\x00" * 32)
                return fake_mount_proc
            if "fusermount" in tool:
                return fake_umount_proc
            return fake_be_proc

        def _which(name: str) -> str | None:
            return {
                "ewfmount": "/usr/bin/ewfmount",
                "bulk_extractor": "/usr/bin/bulk_extractor",
                "fusermount": "/usr/bin/fusermount",
            }.get(name)

        with (
            patch("asyncio.create_subprocess_exec", side_effect=_fake_subprocess),
            patch("shutil.which", side_effect=_which),
            patch(
                "agentropix_mcp.wrappers.bulk_extractor.tempfile.mkdtemp",
                side_effect=_tracking_mkdtemp,
            ),
        ):
            await run_bulk_extractor(image, out, zap=True, timeout=30.0)

        for d in created_tmpdirs:
            assert not Path(d).exists(), f"EWF tmpdir {d} leaked after fusermount rc=1"


# ---------------------------------------------------------------------------
# Test 7 — R4: memory monitor task is cancelled after TimeoutError
# ---------------------------------------------------------------------------


class TestMemoryMonitorCancelledOnTimeout:
    """R4: run_with_memory_limit cancels the monitor task when TimeoutError fires."""

    @pytest.mark.asyncio
    async def test_memory_monitor_task_does_not_orphan_on_timeout(self) -> None:
        """The asyncio monitor task is done (cancelled) after TimeoutError propagates."""
        from agentropix_mcp.wrappers._subprocess import run_with_memory_limit

        fake_proc = MagicMock()
        fake_proc.pid = 77777
        fake_proc.returncode = None
        fake_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
        fake_proc.kill = MagicMock()

        # A hanging monitor that stays pending until cancelled — lets us observe state.
        barrier = asyncio.Event()

        async def _hanging_monitor(*args, **kwargs):
            await barrier.wait()

        captured_tasks: list[asyncio.Task] = []
        real_create_task = asyncio.create_task

        def _tracking_create_task(coro, **kwargs):
            t = real_create_task(coro, **kwargs)
            captured_tasks.append(t)
            return t

        with (
            patch("agentropix_mcp.wrappers._subprocess._get_mem_limit_mb", return_value=512),
            patch("agentropix_mcp.wrappers._subprocess._monitor_memory", side_effect=_hanging_monitor),
            patch("agentropix_mcp.wrappers._subprocess.asyncio.create_task", side_effect=_tracking_create_task),
        ):
            with pytest.raises((TimeoutError, asyncio.TimeoutError)):
                await run_with_memory_limit(fake_proc, timeout=0.001, tool_name="test-tool")

        # Allow the event loop to process the CancelledError from cancel()
        await asyncio.sleep(0)

        assert captured_tasks, "no asyncio task was created for the memory monitor"
        assert all(t.done() for t in captured_tasks), (
            "monitor task is still pending — cancel() was not called on TimeoutError"
        )


# ---------------------------------------------------------------------------
# Test 8 — R5a: Volatility subprocess is killed on timeout
# ---------------------------------------------------------------------------


class TestVolatilityTimeoutKill:
    """R5a: vol subprocess receives kill() when TimeoutError fires."""

    @pytest.mark.asyncio
    async def test_volatility_subprocess_killed_on_timeout(self, tmp_path: Path) -> None:
        """run_with_memory_limit kills the vol subprocess when it exceeds timeout."""
        from agentropix_mcp.wrappers.volatility import get_pslist

        fake_proc = MagicMock()
        fake_proc.pid = 55555
        fake_proc.returncode = None
        fake_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
        fake_proc.kill = MagicMock()
        fake_proc.wait = AsyncMock(return_value=None)

        image = tmp_path / "memory.lime"
        image.write_bytes(b"\x00" * 512)

        with (
            patch("asyncio.create_subprocess_exec", return_value=fake_proc),
            patch("shutil.which", return_value="/usr/bin/vol"),
            patch("agentropix_mcp.wrappers._subprocess._get_mem_limit_mb", return_value=0),
        ):
            with pytest.raises((TimeoutError, asyncio.TimeoutError)):
                await get_pslist(image, timeout=0.001)

        fake_proc.kill.assert_called_once()


# ---------------------------------------------------------------------------
# Test 9 — R5b: YARA subprocess is killed on timeout
# ---------------------------------------------------------------------------


class TestYaraTimeoutKill:
    """R5b: yara proc.kill() fires on TimeoutError."""

    @pytest.mark.asyncio
    async def test_yara_process_group_cleanup_on_kill(self, tmp_path: Path) -> None:
        """scan_yara calls proc.kill() when the subprocess exceeds timeout."""
        from agentropix_mcp.wrappers.yara import scan_yara

        target = tmp_path / "evidence.dd"
        target.write_bytes(b"\x00" * 512)
        rules_file = tmp_path / "rules.yar"
        rules_file.write_text('rule test { condition: false }')

        fake_proc = MagicMock()
        fake_proc.returncode = None
        fake_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
        fake_proc.kill = MagicMock()

        with (
            patch("asyncio.create_subprocess_exec", return_value=fake_proc),
            patch("shutil.which", return_value="/usr/bin/yara"),
        ):
            with pytest.raises((TimeoutError, asyncio.TimeoutError)):
                await scan_yara(target, [rules_file], timeout=0.001)

        fake_proc.kill.assert_called_once()
