"""Tests for MCP server endpoints and tool registration."""

import json
from unittest.mock import patch

import pytest

import sys
sys.path.insert(0, str(__file__).replace("/tests/test_mcp_server.py", "/src"))

from hids_mcp.server import (
    mcp,
    analyze_auth_logs,
    detect_brute_force,
    check_suspicious_processes,
    monitor_network_connections,
    check_listening_ports,
    check_file_integrity,
    generate_security_report,
)


class TestMcpServerSetup:
    """Tests for MCP server configuration."""

    def test_mcp_server_name(self):
        """Test MCP server has correct name."""
        assert mcp.name == "hids"

    def test_mcp_server_exists(self):
        """Test MCP server is instantiated."""
        assert mcp is not None


class TestToolEndpoints:
    """Tests for MCP tool endpoint functionality."""

    @pytest.mark.asyncio
    async def test_analyze_auth_logs_returns_json(self, sample_auth_log):
        """Test analyze_auth_logs returns valid JSON."""
        result = await analyze_auth_logs(log_path=str(sample_auth_log))

        # Should be valid JSON
        data = json.loads(result)
        assert isinstance(data, dict)
        assert "success" in data

    @pytest.mark.asyncio
    async def test_detect_brute_force_returns_json(self, sample_auth_log):
        """Test detect_brute_force returns valid JSON."""
        result = await detect_brute_force(log_path=str(sample_auth_log))

        data = json.loads(result)
        assert isinstance(data, dict)
        assert "success" in data

    @pytest.mark.asyncio
    async def test_check_suspicious_processes_returns_json(self):
        """Test check_suspicious_processes returns valid JSON."""
        result = await check_suspicious_processes()

        data = json.loads(result)
        assert isinstance(data, dict)
        assert "success" in data

    @pytest.mark.asyncio
    async def test_monitor_network_connections_returns_json(self):
        """Test monitor_network_connections returns valid JSON."""
        with patch('psutil.net_connections', return_value=[]):
            result = await monitor_network_connections()

            data = json.loads(result)
            assert isinstance(data, dict)
            assert "success" in data

    @pytest.mark.asyncio
    async def test_check_listening_ports_returns_json(self):
        """Test check_listening_ports returns valid JSON."""
        with patch('psutil.net_connections', return_value=[]):
            result = await check_listening_ports()

            data = json.loads(result)
            assert isinstance(data, dict)
            assert "success" in data

    @pytest.mark.asyncio
    async def test_check_file_integrity_returns_json(self, critical_files):
        """Test check_file_integrity returns valid JSON."""
        result = await check_file_integrity(files=list(critical_files.values()))

        data = json.loads(result)
        assert isinstance(data, dict)
        assert "success" in data

    @pytest.mark.asyncio
    async def test_generate_security_report_returns_json(self):
        """Test generate_security_report returns valid JSON."""
        with patch('psutil.net_connections', return_value=[]):
            result = await generate_security_report()

            data = json.loads(result)
            assert isinstance(data, dict)
            assert "success" in data


class TestToolErrorHandling:
    """Tests for error handling in tools."""

    @pytest.mark.asyncio
    async def test_analyze_auth_logs_missing_file(self):
        """Test graceful handling of missing file."""
        result = await analyze_auth_logs(log_path="/nonexistent/path/file.log")
        data = json.loads(result)

        assert data["success"] is False
        assert "error" in data

    @pytest.mark.asyncio
    async def test_detect_brute_force_missing_file(self):
        """Test graceful handling of missing file."""
        result = await detect_brute_force(log_path="/nonexistent/path/file.log")
        data = json.loads(result)

        assert data["success"] is False
        assert "error" in data


class TestToolIntegration:
    """Integration tests for tool workflows."""

    @pytest.mark.asyncio
    async def test_full_analysis_workflow(self, brute_force_auth_log, critical_files):
        """Test complete analysis workflow."""
        with patch('psutil.net_connections', return_value=[]):
            # Step 1: Analyze auth logs
            auth_analysis = json.loads(await analyze_auth_logs(log_path=str(brute_force_auth_log)))
            assert auth_analysis["success"] is True

            # Step 2: Detect brute force
            brute_force = json.loads(await detect_brute_force(log_path=str(brute_force_auth_log)))
            assert brute_force["success"] is True

            # Step 3: Check processes
            processes = json.loads(await check_suspicious_processes())
            assert processes["success"] is True

            # Step 4: Check network
            network = json.loads(await monitor_network_connections())
            assert network["success"] is True

            # Step 5: Check listening ports
            ports = json.loads(await check_listening_ports())
            assert ports["success"] is True

            # Step 6: Check file integrity
            integrity = json.loads(await check_file_integrity(files=list(critical_files.values())))
            assert integrity["success"] is True

            # Step 7: Generate comprehensive report
            report = json.loads(await generate_security_report())
            assert report["success"] is True

    @pytest.mark.asyncio
    async def test_brute_force_consistency(self, brute_force_auth_log):
        """Test brute force detection is consistent across tools."""
        auth_analysis = json.loads(await analyze_auth_logs(log_path=str(brute_force_auth_log)))
        brute_force = json.loads(await detect_brute_force(log_path=str(brute_force_auth_log)))

        # Both should detect the attack
        auth_alerts = [a for a in auth_analysis["alerts"] if a["type"] == "brute_force"]
        assert len(auth_alerts) >= 1
        assert brute_force["attack_detected"] is True

        # Same attacker IP should be identified
        top_ip = list(auth_analysis["top_failed_ips"].keys())[0]
        attacker_ip = brute_force["attackers"][0]["ip"]
        assert top_ip == attacker_ip


class TestOutputFormatConsistency:
    """Tests for consistent output formatting."""

    @pytest.mark.asyncio
    async def test_all_tools_return_success_field(self, sample_auth_log, critical_files):
        """Test all tools include success field in response."""
        with patch('psutil.net_connections', return_value=[]):
            tools = [
                analyze_auth_logs(log_path=str(sample_auth_log)),
                detect_brute_force(log_path=str(sample_auth_log)),
                check_suspicious_processes(),
                monitor_network_connections(),
                check_listening_ports(),
                check_file_integrity(files=list(critical_files.values())),
                generate_security_report(),
            ]

            for tool_coro in tools:
                result = await tool_coro
                data = json.loads(result)
                assert "success" in data, f"Missing 'success' field in {result[:100]}"

    @pytest.mark.asyncio
    async def test_error_responses_have_error_field(self):
        """Test error responses include error field."""
        error_tools = [
            analyze_auth_logs(log_path="/nonexistent.log"),
            detect_brute_force(log_path="/nonexistent.log"),
        ]

        for tool_coro in error_tools:
            result = await tool_coro
            data = json.loads(result)
            assert data["success"] is False
            assert "error" in data

    @pytest.mark.asyncio
    async def test_json_output_is_indented(self, sample_auth_log):
        """Test JSON output is formatted with indentation."""
        result = await analyze_auth_logs(log_path=str(sample_auth_log))

        # Indented JSON should have newlines
        assert "\n" in result
        # Should be parseable
        json.loads(result)


class TestToolParameters:
    """Tests for tool parameter handling."""

    @pytest.mark.asyncio
    async def test_analyze_auth_logs_custom_hours(self, sample_auth_log):
        """Test custom hours parameter."""
        result = await analyze_auth_logs(log_path=str(sample_auth_log), hours=48)
        data = json.loads(result)

        assert data["success"] is True
        assert data["time_window_hours"] == 48

    @pytest.mark.asyncio
    async def test_analyze_auth_logs_max_lines(self, sample_auth_log):
        """Test max_lines parameter."""
        result = await analyze_auth_logs(log_path=str(sample_auth_log), max_lines=10)
        data = json.loads(result)

        assert data["success"] is True

    @pytest.mark.asyncio
    async def test_detect_brute_force_custom_threshold(self, brute_force_auth_log):
        """Test custom threshold parameter."""
        result = await detect_brute_force(log_path=str(brute_force_auth_log), threshold=100)
        data = json.loads(result)

        assert data["success"] is True
        assert data["threshold"] == 100

    @pytest.mark.asyncio
    async def test_check_file_integrity_with_baseline(self, critical_files, file_integrity_baseline):
        """Test file integrity check with baseline."""
        result = await check_file_integrity(
            files=list(critical_files.values()),
            baseline_path=str(file_integrity_baseline)
        )
        data = json.loads(result)

        assert data["success"] is True
        assert data["baseline_used"] is True


class TestToolDocstrings:
    """Tests for tool documentation."""

    def test_analyze_auth_logs_has_docstring(self):
        """Test analyze_auth_logs has documentation."""
        assert analyze_auth_logs.__doc__ is not None
        assert len(analyze_auth_logs.__doc__) > 0

    def test_detect_brute_force_has_docstring(self):
        """Test detect_brute_force has documentation."""
        assert detect_brute_force.__doc__ is not None
        assert len(detect_brute_force.__doc__) > 0

    def test_check_suspicious_processes_has_docstring(self):
        """Test check_suspicious_processes has documentation."""
        assert check_suspicious_processes.__doc__ is not None
        assert len(check_suspicious_processes.__doc__) > 0

    def test_monitor_network_connections_has_docstring(self):
        """Test monitor_network_connections has documentation."""
        assert monitor_network_connections.__doc__ is not None
        assert len(monitor_network_connections.__doc__) > 0

    def test_check_listening_ports_has_docstring(self):
        """Test check_listening_ports has documentation."""
        assert check_listening_ports.__doc__ is not None
        assert len(check_listening_ports.__doc__) > 0

    def test_check_file_integrity_has_docstring(self):
        """Test check_file_integrity has documentation."""
        assert check_file_integrity.__doc__ is not None
        assert len(check_file_integrity.__doc__) > 0

    def test_generate_security_report_has_docstring(self):
        """Test generate_security_report has documentation."""
        assert generate_security_report.__doc__ is not None
        assert len(generate_security_report.__doc__) > 0
