"""Tests for network connection monitoring functionality."""

import json
import socket
from unittest.mock import MagicMock, patch

import pytest

import sys
sys.path.insert(0, str(__file__).replace("/tests/test_network_monitoring.py", "/src"))

from hids_mcp.server import (
    monitor_network_connections,
    check_listening_ports,
)


class TestMonitorNetworkConnections:
    """Tests for monitor_network_connections function with mocked psutil."""

    @pytest.fixture
    def mock_empty_connections(self):
        """Mock empty network connections."""
        return []

    @pytest.mark.asyncio
    async def test_returns_valid_json(self, mock_empty_connections):
        """Test that function returns valid JSON."""
        with patch('psutil.net_connections', return_value=mock_empty_connections):
            result = await monitor_network_connections()
            data = json.loads(result)

            assert isinstance(data, dict)
            assert "success" in data

    @pytest.mark.asyncio
    async def test_returns_success(self, mock_empty_connections):
        """Test that function returns success."""
        with patch('psutil.net_connections', return_value=mock_empty_connections):
            result = await monitor_network_connections()
            data = json.loads(result)

            assert data["success"] is True

    @pytest.mark.asyncio
    async def test_returns_connection_count(self, mock_empty_connections):
        """Test that total connection count is returned."""
        with patch('psutil.net_connections', return_value=mock_empty_connections):
            result = await monitor_network_connections()
            data = json.loads(result)

            assert "total_connections" in data
            assert data["total_connections"] >= 0

    @pytest.mark.asyncio
    async def test_returns_connection_summary(self, mock_empty_connections):
        """Test that connection summary by status is returned."""
        with patch('psutil.net_connections', return_value=mock_empty_connections):
            result = await monitor_network_connections()
            data = json.loads(result)

            assert "connection_summary" in data
            assert isinstance(data["connection_summary"], dict)

    @pytest.mark.asyncio
    async def test_returns_established_count(self, mock_empty_connections):
        """Test that established connection count is returned."""
        with patch('psutil.net_connections', return_value=mock_empty_connections):
            result = await monitor_network_connections()
            data = json.loads(result)

            assert "established_connections" in data
            assert data["established_connections"] >= 0

    @pytest.mark.asyncio
    async def test_returns_suspicious_connections(self, mock_empty_connections):
        """Test that suspicious connections list is returned."""
        with patch('psutil.net_connections', return_value=mock_empty_connections):
            result = await monitor_network_connections()
            data = json.loads(result)

            assert "suspicious_connections" in data
            assert isinstance(data["suspicious_connections"], list)

    @pytest.mark.asyncio
    async def test_returns_risk_level(self, mock_empty_connections):
        """Test that risk level is returned."""
        with patch('psutil.net_connections', return_value=mock_empty_connections):
            result = await monitor_network_connections()
            data = json.loads(result)

            assert "risk_level" in data
            assert data["risk_level"] in ["low", "medium", "high"]


class TestNetworkConnectionDetection:
    """Tests for network connection detection with mocked data."""

    @pytest.fixture
    def mock_normal_connections(self):
        """Mock normal network connections."""
        conn1 = MagicMock()
        conn1.family = socket.AF_INET
        conn1.type = socket.SOCK_STREAM
        conn1.laddr = MagicMock(ip="0.0.0.0", port=22)
        conn1.raddr = None
        conn1.status = "LISTEN"
        conn1.pid = 100

        conn2 = MagicMock()
        conn2.family = socket.AF_INET
        conn2.type = socket.SOCK_STREAM
        conn2.laddr = MagicMock(ip="192.168.1.10", port=22)
        conn2.raddr = MagicMock(ip="192.168.1.100", port=50000)
        conn2.status = "ESTABLISHED"
        conn2.pid = 100

        return [conn1, conn2]

    @pytest.fixture
    def mock_suspicious_connections(self):
        """Mock suspicious network connections."""
        # Normal connection
        conn1 = MagicMock()
        conn1.family = socket.AF_INET
        conn1.type = socket.SOCK_STREAM
        conn1.laddr = MagicMock(ip="0.0.0.0", port=22)
        conn1.raddr = None
        conn1.status = "LISTEN"
        conn1.pid = 100

        # Suspicious: connection to known C2 port
        conn2 = MagicMock()
        conn2.family = socket.AF_INET
        conn2.type = socket.SOCK_STREAM
        conn2.laddr = MagicMock(ip="192.168.1.10", port=45678)
        conn2.raddr = MagicMock(ip="10.0.0.50", port=4444)
        conn2.status = "ESTABLISHED"
        conn2.pid = 1001

        # Suspicious: listening on backdoor port
        conn3 = MagicMock()
        conn3.family = socket.AF_INET
        conn3.type = socket.SOCK_STREAM
        conn3.laddr = MagicMock(ip="0.0.0.0", port=31337)
        conn3.raddr = None
        conn3.status = "LISTEN"
        conn3.pid = 1002

        return [conn1, conn2, conn3]

    @pytest.mark.asyncio
    async def test_detect_suspicious_port(self, mock_suspicious_connections):
        """Test detection of connections to suspicious ports."""
        with patch('psutil.net_connections', return_value=mock_suspicious_connections):
            with patch('psutil.Process') as mock_process:
                mock_process.return_value.name.return_value = "nc"

                result = await monitor_network_connections()
                data = json.loads(result)

                assert len(data["suspicious_connections"]) >= 1

    @pytest.mark.asyncio
    async def test_no_suspicious_normal_connections(self, mock_normal_connections):
        """Test no false positives on normal connections."""
        with patch('psutil.net_connections', return_value=mock_normal_connections):
            with patch('psutil.Process') as mock_process:
                mock_process.return_value.name.return_value = "sshd"

                result = await monitor_network_connections()
                data = json.loads(result)

                assert len(data["suspicious_connections"]) == 0
                assert data["risk_level"] == "low"

    @pytest.mark.asyncio
    async def test_connection_details(self, mock_normal_connections):
        """Test connection details are captured."""
        with patch('psutil.net_connections', return_value=mock_normal_connections):
            with patch('psutil.Process') as mock_process:
                mock_process.return_value.name.return_value = "sshd"

                result = await monitor_network_connections()
                data = json.loads(result)

                # Should have connection summary
                assert "LISTEN" in data["connection_summary"] or "ESTABLISHED" in data["connection_summary"]

    @pytest.mark.asyncio
    async def test_external_connections_filtered(self, mock_normal_connections):
        """Test external connections are identified."""
        with patch('psutil.net_connections', return_value=mock_normal_connections):
            with patch('psutil.Process') as mock_process:
                mock_process.return_value.name.return_value = "sshd"

                result = await monitor_network_connections()
                data = json.loads(result)

                assert "external_connections" in data
                assert isinstance(data["external_connections"], list)


class TestCheckListeningPorts:
    """Tests for check_listening_ports function with mocked psutil."""

    @pytest.fixture
    def mock_empty_connections(self):
        """Mock empty network connections."""
        return []

    @pytest.mark.asyncio
    async def test_returns_valid_json(self, mock_empty_connections):
        """Test that function returns valid JSON."""
        with patch('psutil.net_connections', return_value=mock_empty_connections):
            result = await check_listening_ports()
            data = json.loads(result)

            assert isinstance(data, dict)
            assert "success" in data

    @pytest.mark.asyncio
    async def test_returns_success(self, mock_empty_connections):
        """Test that function returns success."""
        with patch('psutil.net_connections', return_value=mock_empty_connections):
            result = await check_listening_ports()
            data = json.loads(result)

            assert data["success"] is True

    @pytest.mark.asyncio
    async def test_returns_listener_count(self, mock_empty_connections):
        """Test that total listener count is returned."""
        with patch('psutil.net_connections', return_value=mock_empty_connections):
            result = await check_listening_ports()
            data = json.loads(result)

            assert "total_listeners" in data
            assert data["total_listeners"] >= 0

    @pytest.mark.asyncio
    async def test_returns_all_listeners(self, mock_empty_connections):
        """Test that all listeners list is returned."""
        with patch('psutil.net_connections', return_value=mock_empty_connections):
            result = await check_listening_ports()
            data = json.loads(result)

            assert "all_listeners" in data
            assert isinstance(data["all_listeners"], list)

    @pytest.mark.asyncio
    async def test_returns_unexpected_listeners(self, mock_empty_connections):
        """Test that unexpected listeners are identified."""
        with patch('psutil.net_connections', return_value=mock_empty_connections):
            result = await check_listening_ports()
            data = json.loads(result)

            assert "unexpected_listeners" in data
            assert isinstance(data["unexpected_listeners"], list)

    @pytest.mark.asyncio
    async def test_returns_port_summary(self, mock_empty_connections):
        """Test that port summary is returned."""
        with patch('psutil.net_connections', return_value=mock_empty_connections):
            result = await check_listening_ports()
            data = json.loads(result)

            assert "port_summary" in data
            assert "privileged_ports" in data["port_summary"]
            assert "high_ports" in data["port_summary"]

    @pytest.mark.asyncio
    async def test_returns_recommendations(self, mock_empty_connections):
        """Test that recommendations are provided."""
        with patch('psutil.net_connections', return_value=mock_empty_connections):
            result = await check_listening_ports()
            data = json.loads(result)

            assert "recommendations" in data
            assert isinstance(data["recommendations"], list)


class TestListeningPortsDetection:
    """Tests for listening port detection with mocked data."""

    @pytest.fixture
    def mock_normal_listeners(self):
        """Mock normal listening ports."""
        listeners = []
        normal_ports = [22, 80, 443]

        for port in normal_ports:
            conn = MagicMock()
            conn.family = socket.AF_INET
            conn.laddr = MagicMock(ip="0.0.0.0", port=port)
            conn.status = "LISTEN"
            conn.pid = port * 10
            listeners.append(conn)

        return listeners

    @pytest.fixture
    def mock_suspicious_listeners(self):
        """Mock suspicious listening ports."""
        listeners = []

        # Normal port
        conn1 = MagicMock()
        conn1.family = socket.AF_INET
        conn1.laddr = MagicMock(ip="0.0.0.0", port=22)
        conn1.status = "LISTEN"
        conn1.pid = 100
        listeners.append(conn1)

        # Suspicious high port
        conn2 = MagicMock()
        conn2.family = socket.AF_INET
        conn2.laddr = MagicMock(ip="0.0.0.0", port=31337)
        conn2.status = "LISTEN"
        conn2.pid = 1001
        listeners.append(conn2)

        # Another suspicious port
        conn3 = MagicMock()
        conn3.family = socket.AF_INET
        conn3.laddr = MagicMock(ip="0.0.0.0", port=4444)
        conn3.status = "LISTEN"
        conn3.pid = 1002
        listeners.append(conn3)

        return listeners

    @pytest.mark.asyncio
    async def test_identify_unexpected_ports(self, mock_suspicious_listeners):
        """Test identification of unexpected listening ports."""
        with patch('psutil.net_connections', return_value=mock_suspicious_listeners):
            with patch('psutil.Process') as mock_process:
                mock_process.return_value.name.return_value = "unknown"
                mock_process.return_value.username.return_value = "nobody"

                result = await check_listening_ports()
                data = json.loads(result)

                # Should identify unexpected ports
                assert len(data["unexpected_listeners"]) >= 1

    @pytest.mark.asyncio
    async def test_no_unexpected_normal_ports(self, mock_normal_listeners):
        """Test no false positives for normal ports."""
        with patch('psutil.net_connections', return_value=mock_normal_listeners):
            with patch('psutil.Process') as mock_process:
                mock_process.return_value.name.return_value = "sshd"
                mock_process.return_value.username.return_value = "root"

                result = await check_listening_ports()
                data = json.loads(result)

                # Common ports should not be flagged as unexpected
                unexpected_ports = [l["port"] for l in data["unexpected_listeners"]]
                assert 22 not in unexpected_ports
                assert 80 not in unexpected_ports
                assert 443 not in unexpected_ports

    @pytest.mark.asyncio
    async def test_listener_details(self, mock_normal_listeners):
        """Test listener details are captured."""
        with patch('psutil.net_connections', return_value=mock_normal_listeners):
            with patch('psutil.Process') as mock_process:
                mock_process.return_value.name.return_value = "sshd"
                mock_process.return_value.username.return_value = "root"

                result = await check_listening_ports()
                data = json.loads(result)

                for listener in data["all_listeners"]:
                    assert "port" in listener
                    assert "address" in listener
                    assert "pid" in listener

    @pytest.mark.asyncio
    async def test_sorted_by_port(self, mock_suspicious_listeners):
        """Test listeners are sorted by port number."""
        with patch('psutil.net_connections', return_value=mock_suspicious_listeners):
            with patch('psutil.Process') as mock_process:
                mock_process.return_value.name.return_value = "unknown"
                mock_process.return_value.username.return_value = "nobody"

                result = await check_listening_ports()
                data = json.loads(result)

                ports = [l["port"] for l in data["all_listeners"]]
                assert ports == sorted(ports)


class TestNetworkSuspiciousPorts:
    """Tests for suspicious port detection."""

    def test_c2_ports_detected(self, suspicious_ports):
        """Test known C2 ports are in suspicious list."""
        expected_suspicious = [4444, 5555, 1337, 31337]
        for port in expected_suspicious:
            assert port in suspicious_ports

    @pytest.mark.asyncio
    async def test_detects_port_4444(self):
        """Test detection of Metasploit default port."""
        conn = MagicMock()
        conn.family = socket.AF_INET
        conn.type = socket.SOCK_STREAM
        conn.laddr = MagicMock(ip="192.168.1.10", port=12345)
        conn.raddr = MagicMock(ip="10.0.0.1", port=4444)
        conn.status = "ESTABLISHED"
        conn.pid = 1001

        with patch('psutil.net_connections', return_value=[conn]):
            with patch('psutil.Process') as mock_process:
                mock_process.return_value.name.return_value = "shell"

                result = await monitor_network_connections()
                data = json.loads(result)

                assert len(data["suspicious_connections"]) >= 1


class TestNetworkMonitoringEdgeCases:
    """Tests for edge cases in network monitoring."""

    @pytest.mark.asyncio
    async def test_handles_no_connections(self):
        """Test handling when no connections exist."""
        with patch('psutil.net_connections', return_value=[]):
            result = await monitor_network_connections()
            data = json.loads(result)

            assert data["success"] is True
            assert data["total_connections"] == 0

    @pytest.mark.asyncio
    async def test_handles_no_listeners(self):
        """Test handling when no listeners exist."""
        with patch('psutil.net_connections', return_value=[]):
            result = await check_listening_ports()
            data = json.loads(result)

            assert data["success"] is True
            assert data["total_listeners"] == 0

    @pytest.mark.asyncio
    async def test_handles_process_gone(self):
        """Test handling when process disappears during scan."""
        conn = MagicMock()
        conn.family = socket.AF_INET
        conn.type = socket.SOCK_STREAM
        conn.laddr = MagicMock(ip="0.0.0.0", port=22)
        conn.raddr = None
        conn.status = "LISTEN"
        conn.pid = 100

        import psutil
        with patch('psutil.net_connections', return_value=[conn]):
            with patch('psutil.Process', side_effect=psutil.NoSuchProcess(100)):
                result = await monitor_network_connections()
                data = json.loads(result)

                # Should still succeed
                assert data["success"] is True
