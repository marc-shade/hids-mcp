"""Tests for security report generation functionality."""

import json
from datetime import datetime
from unittest.mock import patch, AsyncMock

import pytest

import sys
sys.path.insert(0, str(__file__).replace("/tests/test_security_report.py", "/src"))

from hids_mcp.server import generate_security_report


class TestGenerateSecurityReport:
    """Tests for generate_security_report function."""

    @pytest.mark.asyncio
    async def test_returns_valid_json(self):
        """Test that function returns valid JSON."""
        with patch('psutil.net_connections', return_value=[]):
            result = await generate_security_report()
            data = json.loads(result)

            assert isinstance(data, dict)
            assert "success" in data

    @pytest.mark.asyncio
    async def test_returns_success(self):
        """Test that function returns success."""
        with patch('psutil.net_connections', return_value=[]):
            result = await generate_security_report()
            data = json.loads(result)

            assert data["success"] is True

    @pytest.mark.asyncio
    async def test_returns_report_time(self):
        """Test that report time is included."""
        with patch('psutil.net_connections', return_value=[]):
            result = await generate_security_report()
            data = json.loads(result)

            assert "report_time" in data
            # Should be valid ISO format
            datetime.fromisoformat(data["report_time"])

    @pytest.mark.asyncio
    async def test_returns_hostname(self):
        """Test that hostname is included."""
        with patch('psutil.net_connections', return_value=[]):
            result = await generate_security_report()
            data = json.loads(result)

            assert "hostname" in data
            assert isinstance(data["hostname"], str)
            assert len(data["hostname"]) > 0

    @pytest.mark.asyncio
    async def test_returns_sections(self):
        """Test that report sections are included."""
        with patch('psutil.net_connections', return_value=[]):
            result = await generate_security_report()
            data = json.loads(result)

            assert "sections" in data
            assert isinstance(data["sections"], list)

    @pytest.mark.asyncio
    async def test_returns_overall_risk(self):
        """Test that overall risk level is included."""
        with patch('psutil.net_connections', return_value=[]):
            result = await generate_security_report()
            data = json.loads(result)

            assert "overall_risk" in data
            assert data["overall_risk"] in ["low", "medium", "high"]

    @pytest.mark.asyncio
    async def test_returns_alerts(self):
        """Test that alerts list is included."""
        with patch('psutil.net_connections', return_value=[]):
            result = await generate_security_report()
            data = json.loads(result)

            assert "alerts" in data
            assert isinstance(data["alerts"], list)

    @pytest.mark.asyncio
    async def test_returns_alert_summary(self):
        """Test that alert summary is included."""
        with patch('psutil.net_connections', return_value=[]):
            result = await generate_security_report()
            data = json.loads(result)

            assert "alert_summary" in data
            assert "total" in data["alert_summary"]
            assert "high" in data["alert_summary"]
            assert "medium" in data["alert_summary"]


class TestSecurityReportSections:
    """Tests for security report section generation."""

    @pytest.mark.asyncio
    async def test_has_authentication_section(self):
        """Test that Authentication section is included when auth log available."""
        # Mock auth log analysis to return success
        mock_auth = json.dumps({
            "success": True,
            "summary": {"failed_logins": 0, "successful_logins": 10, "invalid_user_attempts": 0, "sudo_commands": 0},
            "alerts": [],
            "top_failed_ips": {},
            "top_failed_users": {},
            "successful_users": {"admin": 10},
            "recent_sudo": [],
            "recent_failures": []
        })

        with patch('psutil.net_connections', return_value=[]):
            with patch('hids_mcp.server.analyze_auth_logs', return_value=mock_auth):
                result = await generate_security_report()
                data = json.loads(result)

                section_names = [s["name"] for s in data["sections"]]
                assert "Authentication" in section_names

    @pytest.mark.asyncio
    async def test_has_processes_section(self):
        """Test that Processes section is included."""
        with patch('psutil.net_connections', return_value=[]):
            result = await generate_security_report()
            data = json.loads(result)

            section_names = [s["name"] for s in data["sections"]]
            assert "Processes" in section_names

    @pytest.mark.asyncio
    async def test_has_network_section(self):
        """Test that Network section is included."""
        with patch('psutil.net_connections', return_value=[]):
            result = await generate_security_report()
            data = json.loads(result)

            section_names = [s["name"] for s in data["sections"]]
            assert "Network" in section_names

    @pytest.mark.asyncio
    async def test_has_listening_services_section(self):
        """Test that Listening Services section is included."""
        with patch('psutil.net_connections', return_value=[]):
            result = await generate_security_report()
            data = json.loads(result)

            section_names = [s["name"] for s in data["sections"]]
            assert "Listening Services" in section_names

    @pytest.mark.asyncio
    async def test_has_file_integrity_section(self):
        """Test that File Integrity section is included."""
        with patch('psutil.net_connections', return_value=[]):
            result = await generate_security_report()
            data = json.loads(result)

            section_names = [s["name"] for s in data["sections"]]
            assert "File Integrity" in section_names


class TestSecurityReportRiskCalculation:
    """Tests for security report risk calculation."""

    @pytest.mark.asyncio
    async def test_high_risk_with_high_alerts(self):
        """Test that high severity alerts result in high risk."""
        # Mock the component functions to return high severity alerts
        mock_auth = json.dumps({
            "success": True,
            "summary": {"failed_logins": 100, "successful_logins": 0, "invalid_user_attempts": 50, "sudo_commands": 0},
            "alerts": [{"type": "brute_force", "severity": "high", "description": "Brute force detected"}],
            "top_failed_ips": {},
            "top_failed_users": {},
            "successful_users": {},
            "recent_sudo": [],
            "recent_failures": []
        })

        mock_proc = json.dumps({
            "success": True,
            "total_processes": 100,
            "suspicious_count": 5,
            "suspicious_processes": [],
            "risk_level": "high",
            "recommendations": []
        })

        mock_net = json.dumps({
            "success": True,
            "total_connections": 50,
            "connection_summary": {},
            "established_connections": 10,
            "suspicious_connections": [],
            "external_connections": [],
            "risk_level": "low"
        })

        mock_ports = json.dumps({
            "success": True,
            "total_listeners": 5,
            "all_listeners": [],
            "unexpected_listeners": [],
            "port_summary": {"privileged_ports": 3, "high_ports": 2},
            "recommendations": []
        })

        mock_files = json.dumps({
            "success": True,
            "files_checked": 10,
            "changed_files": 0,
            "missing_files": 0,
            "results": [],
            "alerts": [],
            "baseline_used": False,
            "current_hashes": {}
        })

        with patch('hids_mcp.server.analyze_auth_logs', return_value=mock_auth):
            with patch('hids_mcp.server.check_suspicious_processes', return_value=mock_proc):
                with patch('hids_mcp.server.monitor_network_connections', return_value=mock_net):
                    with patch('hids_mcp.server.check_listening_ports', return_value=mock_ports):
                        with patch('hids_mcp.server.check_file_integrity', return_value=mock_files):
                            result = await generate_security_report()
                            data = json.loads(result)

                            assert data["overall_risk"] == "high"

    @pytest.mark.asyncio
    async def test_low_risk_with_no_alerts(self):
        """Test that no alerts result in low risk."""
        # Mock the component functions to return no alerts
        mock_auth = json.dumps({
            "success": True,
            "summary": {"failed_logins": 0, "successful_logins": 10, "invalid_user_attempts": 0, "sudo_commands": 2},
            "alerts": [],
            "top_failed_ips": {},
            "top_failed_users": {},
            "successful_users": {"admin": 10},
            "recent_sudo": [],
            "recent_failures": []
        })

        mock_proc = json.dumps({
            "success": True,
            "total_processes": 100,
            "suspicious_count": 0,
            "suspicious_processes": [],
            "risk_level": "low",
            "recommendations": ["No suspicious processes detected"]
        })

        mock_net = json.dumps({
            "success": True,
            "total_connections": 50,
            "connection_summary": {"ESTABLISHED": 10, "LISTEN": 5},
            "established_connections": 10,
            "suspicious_connections": [],
            "external_connections": [],
            "risk_level": "low"
        })

        mock_ports = json.dumps({
            "success": True,
            "total_listeners": 5,
            "all_listeners": [],
            "unexpected_listeners": [],
            "port_summary": {"privileged_ports": 3, "high_ports": 2},
            "recommendations": ["All listeners appear expected"]
        })

        mock_files = json.dumps({
            "success": True,
            "files_checked": 10,
            "changed_files": 0,
            "missing_files": 0,
            "results": [],
            "alerts": [],
            "baseline_used": True,
            "current_hashes": {}
        })

        with patch('hids_mcp.server.analyze_auth_logs', return_value=mock_auth):
            with patch('hids_mcp.server.check_suspicious_processes', return_value=mock_proc):
                with patch('hids_mcp.server.monitor_network_connections', return_value=mock_net):
                    with patch('hids_mcp.server.check_listening_ports', return_value=mock_ports):
                        with patch('hids_mcp.server.check_file_integrity', return_value=mock_files):
                            result = await generate_security_report()
                            data = json.loads(result)

                            assert data["overall_risk"] == "low"


class TestSecurityReportAlertAggregation:
    """Tests for alert aggregation in security reports."""

    @pytest.mark.asyncio
    async def test_aggregates_auth_alerts(self):
        """Test that auth alerts are aggregated."""
        mock_auth = json.dumps({
            "success": True,
            "summary": {"failed_logins": 100, "successful_logins": 0, "invalid_user_attempts": 50, "sudo_commands": 0},
            "alerts": [
                {"type": "brute_force", "severity": "high", "description": "Brute force detected"},
                {"type": "user_enumeration", "severity": "medium", "description": "User enumeration detected"}
            ],
            "top_failed_ips": {},
            "top_failed_users": {},
            "successful_users": {},
            "recent_sudo": [],
            "recent_failures": []
        })

        mock_proc = json.dumps({
            "success": True,
            "total_processes": 100,
            "suspicious_count": 0,
            "suspicious_processes": [],
            "risk_level": "low",
            "recommendations": []
        })

        mock_net = json.dumps({
            "success": True,
            "total_connections": 50,
            "connection_summary": {},
            "established_connections": 10,
            "suspicious_connections": [],
            "external_connections": [],
            "risk_level": "low"
        })

        mock_ports = json.dumps({
            "success": True,
            "total_listeners": 5,
            "all_listeners": [],
            "unexpected_listeners": [],
            "port_summary": {"privileged_ports": 3, "high_ports": 2},
            "recommendations": []
        })

        mock_files = json.dumps({
            "success": True,
            "files_checked": 10,
            "changed_files": 0,
            "missing_files": 0,
            "results": [],
            "alerts": [],
            "baseline_used": False,
            "current_hashes": {}
        })

        with patch('hids_mcp.server.analyze_auth_logs', return_value=mock_auth):
            with patch('hids_mcp.server.check_suspicious_processes', return_value=mock_proc):
                with patch('hids_mcp.server.monitor_network_connections', return_value=mock_net):
                    with patch('hids_mcp.server.check_listening_ports', return_value=mock_ports):
                        with patch('hids_mcp.server.check_file_integrity', return_value=mock_files):
                            result = await generate_security_report()
                            data = json.loads(result)

                            # Should have alerts from auth analysis
                            alert_types = [a["type"] for a in data["alerts"]]
                            assert "brute_force" in alert_types

    @pytest.mark.asyncio
    async def test_aggregates_process_alerts(self):
        """Test that process alerts are aggregated."""
        mock_auth = json.dumps({
            "success": True,
            "summary": {"failed_logins": 0, "successful_logins": 0, "invalid_user_attempts": 0, "sudo_commands": 0},
            "alerts": [],
            "top_failed_ips": {},
            "top_failed_users": {},
            "successful_users": {},
            "recent_sudo": [],
            "recent_failures": []
        })

        mock_proc = json.dumps({
            "success": True,
            "total_processes": 100,
            "suspicious_count": 3,
            "suspicious_processes": [
                {"pid": 1001, "name": "nc", "reasons": ["Suspicious name"]}
            ],
            "risk_level": "high",
            "recommendations": []
        })

        mock_net = json.dumps({
            "success": True,
            "total_connections": 50,
            "connection_summary": {},
            "established_connections": 10,
            "suspicious_connections": [],
            "external_connections": [],
            "risk_level": "low"
        })

        mock_ports = json.dumps({
            "success": True,
            "total_listeners": 5,
            "all_listeners": [],
            "unexpected_listeners": [],
            "port_summary": {"privileged_ports": 3, "high_ports": 2},
            "recommendations": []
        })

        mock_files = json.dumps({
            "success": True,
            "files_checked": 10,
            "changed_files": 0,
            "missing_files": 0,
            "results": [],
            "alerts": [],
            "baseline_used": False,
            "current_hashes": {}
        })

        with patch('hids_mcp.server.analyze_auth_logs', return_value=mock_auth):
            with patch('hids_mcp.server.check_suspicious_processes', return_value=mock_proc):
                with patch('hids_mcp.server.monitor_network_connections', return_value=mock_net):
                    with patch('hids_mcp.server.check_listening_ports', return_value=mock_ports):
                        with patch('hids_mcp.server.check_file_integrity', return_value=mock_files):
                            result = await generate_security_report()
                            data = json.loads(result)

                            # Should have suspicious processes alert
                            alert_types = [a["type"] for a in data["alerts"]]
                            assert "suspicious_processes" in alert_types


class TestSecurityReportAlertSummary:
    """Tests for alert summary in security reports."""

    @pytest.mark.asyncio
    async def test_alert_summary_counts_correct(self):
        """Test that alert summary counts are correct."""
        mock_auth = json.dumps({
            "success": True,
            "summary": {"failed_logins": 100, "successful_logins": 0, "invalid_user_attempts": 50, "sudo_commands": 0},
            "alerts": [
                {"type": "brute_force", "severity": "high", "description": "Brute force detected"},
                {"type": "user_enumeration", "severity": "medium", "description": "User enumeration detected"}
            ],
            "top_failed_ips": {},
            "top_failed_users": {},
            "successful_users": {},
            "recent_sudo": [],
            "recent_failures": []
        })

        mock_proc = json.dumps({
            "success": True,
            "total_processes": 100,
            "suspicious_count": 1,
            "suspicious_processes": [],
            "risk_level": "high",
            "recommendations": []
        })

        mock_net = json.dumps({
            "success": True,
            "total_connections": 50,
            "connection_summary": {},
            "established_connections": 10,
            "suspicious_connections": [],
            "external_connections": [],
            "risk_level": "low"
        })

        mock_ports = json.dumps({
            "success": True,
            "total_listeners": 5,
            "all_listeners": [],
            "unexpected_listeners": [],
            "port_summary": {"privileged_ports": 3, "high_ports": 2},
            "recommendations": []
        })

        mock_files = json.dumps({
            "success": True,
            "files_checked": 10,
            "changed_files": 0,
            "missing_files": 0,
            "results": [],
            "alerts": [],
            "baseline_used": False,
            "current_hashes": {}
        })

        with patch('hids_mcp.server.analyze_auth_logs', return_value=mock_auth):
            with patch('hids_mcp.server.check_suspicious_processes', return_value=mock_proc):
                with patch('hids_mcp.server.monitor_network_connections', return_value=mock_net):
                    with patch('hids_mcp.server.check_listening_ports', return_value=mock_ports):
                        with patch('hids_mcp.server.check_file_integrity', return_value=mock_files):
                            result = await generate_security_report()
                            data = json.loads(result)

                            # Should have correct counts
                            assert data["alert_summary"]["high"] >= 1
                            assert data["alert_summary"]["medium"] >= 1
                            assert data["alert_summary"]["total"] >= 2
