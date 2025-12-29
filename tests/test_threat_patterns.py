"""Tests for threat pattern definitions and detection."""

import re

import pytest

import sys
sys.path.insert(0, str(__file__).replace("/tests/test_threat_patterns.py", "/src"))

from hids_mcp.server import (
    AUTH_PATTERNS,
    SUSPICIOUS_PROCESS_NAMES,
    SUSPICIOUS_PATHS,
    CRITICAL_FILES,
)


class TestAuthPatternDefinitions:
    """Tests for authentication pattern definitions."""

    def test_failed_password_pattern_exists(self):
        """Test failed_password pattern is defined."""
        assert "failed_password" in AUTH_PATTERNS
        assert isinstance(AUTH_PATTERNS["failed_password"], re.Pattern)

    def test_accepted_password_pattern_exists(self):
        """Test accepted_password pattern is defined."""
        assert "accepted_password" in AUTH_PATTERNS
        assert isinstance(AUTH_PATTERNS["accepted_password"], re.Pattern)

    def test_accepted_key_pattern_exists(self):
        """Test accepted_key pattern is defined."""
        assert "accepted_key" in AUTH_PATTERNS
        assert isinstance(AUTH_PATTERNS["accepted_key"], re.Pattern)

    def test_invalid_user_pattern_exists(self):
        """Test invalid_user pattern is defined."""
        assert "invalid_user" in AUTH_PATTERNS
        assert isinstance(AUTH_PATTERNS["invalid_user"], re.Pattern)

    def test_sudo_pattern_exists(self):
        """Test sudo pattern is defined."""
        assert "sudo" in AUTH_PATTERNS
        assert isinstance(AUTH_PATTERNS["sudo"], re.Pattern)

    def test_session_opened_pattern_exists(self):
        """Test session_opened pattern is defined."""
        assert "session_opened" in AUTH_PATTERNS
        assert isinstance(AUTH_PATTERNS["session_opened"], re.Pattern)

    def test_session_closed_pattern_exists(self):
        """Test session_closed pattern is defined."""
        assert "session_closed" in AUTH_PATTERNS
        assert isinstance(AUTH_PATTERNS["session_closed"], re.Pattern)


class TestAuthPatternMatching:
    """Tests for authentication pattern matching accuracy."""

    def test_failed_password_standard_format(self):
        """Test failed password pattern matches standard format."""
        pattern = AUTH_PATTERNS["failed_password"]
        line = "Dec 29 10:30:00 server sshd[1234]: Failed password for admin from 192.168.1.100 port 50000 ssh2"

        match = pattern.search(line)
        assert match is not None
        user, ip = match.groups()
        assert user == "admin"
        assert ip == "192.168.1.100"

    def test_failed_password_invalid_user_format(self):
        """Test failed password pattern matches invalid user format."""
        pattern = AUTH_PATTERNS["failed_password"]
        line = "Dec 29 10:30:00 server sshd[1234]: Failed password for invalid user hacker from 10.0.0.1 port 40000 ssh2"

        match = pattern.search(line)
        assert match is not None
        user, ip = match.groups()
        assert user == "hacker"
        assert ip == "10.0.0.1"

    def test_accepted_password_format(self):
        """Test accepted password pattern matches correctly."""
        pattern = AUTH_PATTERNS["accepted_password"]
        line = "Dec 29 10:30:00 server sshd[1234]: Accepted password for admin from 192.168.1.10 port 55000 ssh2"

        match = pattern.search(line)
        assert match is not None
        user, ip = match.groups()
        assert user == "admin"
        assert ip == "192.168.1.10"

    def test_accepted_publickey_format(self):
        """Test accepted publickey pattern matches correctly."""
        pattern = AUTH_PATTERNS["accepted_key"]
        line = "Dec 29 10:30:00 server sshd[1234]: Accepted publickey for deploy from 10.0.0.50 port 60000 ssh2"

        match = pattern.search(line)
        assert match is not None
        user, ip = match.groups()
        assert user == "deploy"
        assert ip == "10.0.0.50"

    def test_invalid_user_format(self):
        """Test invalid user pattern matches correctly."""
        pattern = AUTH_PATTERNS["invalid_user"]
        line = "Dec 29 10:30:00 server sshd[1234]: Invalid user testuser from 10.0.0.99 port 45000"

        match = pattern.search(line)
        assert match is not None
        user, ip = match.groups()
        assert user == "testuser"
        assert ip == "10.0.0.99"

    def test_sudo_command_format(self):
        """Test sudo pattern matches correctly."""
        pattern = AUTH_PATTERNS["sudo"]
        line = "Dec 29 10:30:00 server sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/apt update"

        match = pattern.search(line)
        assert match is not None
        user, command = match.groups()
        assert user == "admin"
        assert "/usr/bin/apt update" in command

    def test_session_opened_format(self):
        """Test session opened pattern matches correctly."""
        pattern = AUTH_PATTERNS["session_opened"]
        line = "Dec 29 10:30:00 server sshd[1234]: pam_unix(sshd:session): session opened for user admin"

        match = pattern.search(line)
        assert match is not None
        user = match.group(1)
        assert user == "admin"

    def test_session_closed_format(self):
        """Test session closed pattern matches correctly."""
        pattern = AUTH_PATTERNS["session_closed"]
        line = "Dec 29 10:30:00 server sshd[1234]: pam_unix(sshd:session): session closed for user admin"

        match = pattern.search(line)
        assert match is not None
        user = match.group(1)
        assert user == "admin"


class TestAuthPatternEdgeCases:
    """Tests for edge cases in authentication patterns."""

    def test_failed_password_with_special_username(self):
        """Test failed password with special characters in username."""
        pattern = AUTH_PATTERNS["failed_password"]
        line = "Dec 29 10:30:00 server sshd[1234]: Failed password for user@domain from 192.168.1.100 port 50000 ssh2"

        match = pattern.search(line)
        assert match is not None

    def test_ipv6_address_in_pattern(self):
        """Test patterns work with IPv6 addresses."""
        pattern = AUTH_PATTERNS["failed_password"]
        line = "Dec 29 10:30:00 server sshd[1234]: Failed password for admin from ::1 port 50000 ssh2"

        match = pattern.search(line)
        assert match is not None

    def test_no_match_on_unrelated_line(self):
        """Test patterns don't match unrelated lines."""
        pattern = AUTH_PATTERNS["failed_password"]
        line = "Dec 29 10:30:00 server nginx[1234]: GET /index.html HTTP/1.1"

        match = pattern.search(line)
        assert match is None


class TestSuspiciousProcessNames:
    """Tests for suspicious process name definitions."""

    def test_suspicious_names_is_list(self):
        """Test SUSPICIOUS_PROCESS_NAMES is a list."""
        assert isinstance(SUSPICIOUS_PROCESS_NAMES, list)

    def test_suspicious_names_not_empty(self):
        """Test SUSPICIOUS_PROCESS_NAMES is not empty."""
        assert len(SUSPICIOUS_PROCESS_NAMES) > 0

    def test_contains_netcat_variants(self):
        """Test netcat variants are included."""
        netcat_variants = ["nc", "ncat", "netcat"]
        for variant in netcat_variants:
            assert variant in SUSPICIOUS_PROCESS_NAMES

    def test_contains_crypto_miners(self):
        """Test crypto miner names are included."""
        miners = ["xmrig", "minerd", "cryptominer"]
        for miner in miners:
            assert miner in SUSPICIOUS_PROCESS_NAMES

    def test_contains_pentesting_tools(self):
        """Test pentesting tool names are included."""
        tools = ["metasploit", "hydra", "mimikatz"]
        for tool in tools:
            assert tool in SUSPICIOUS_PROCESS_NAMES

    def test_contains_relay_tools(self):
        """Test network relay tool names are included."""
        assert "socat" in SUSPICIOUS_PROCESS_NAMES


class TestSuspiciousPaths:
    """Tests for suspicious path definitions."""

    def test_suspicious_paths_is_list(self):
        """Test SUSPICIOUS_PATHS is a list."""
        assert isinstance(SUSPICIOUS_PATHS, list)

    def test_suspicious_paths_not_empty(self):
        """Test SUSPICIOUS_PATHS is not empty."""
        assert len(SUSPICIOUS_PATHS) > 0

    def test_contains_tmp_directory(self):
        """Test /tmp/ is included."""
        assert "/tmp/" in SUSPICIOUS_PATHS

    def test_contains_dev_shm(self):
        """Test /dev/shm/ is included."""
        assert "/dev/shm/" in SUSPICIOUS_PATHS

    def test_contains_var_tmp(self):
        """Test /var/tmp/ is included."""
        assert "/var/tmp/" in SUSPICIOUS_PATHS

    def test_paths_end_with_slash(self):
        """Test all paths end with slash for proper prefix matching."""
        for path in SUSPICIOUS_PATHS:
            assert path.endswith("/")


class TestCriticalFiles:
    """Tests for critical file definitions."""

    def test_critical_files_is_list(self):
        """Test CRITICAL_FILES is a list."""
        assert isinstance(CRITICAL_FILES, list)

    def test_critical_files_not_empty(self):
        """Test CRITICAL_FILES is not empty."""
        assert len(CRITICAL_FILES) > 0

    def test_contains_passwd(self):
        """Test /etc/passwd is included."""
        assert "/etc/passwd" in CRITICAL_FILES

    def test_contains_shadow(self):
        """Test /etc/shadow is included."""
        assert "/etc/shadow" in CRITICAL_FILES

    def test_contains_sudoers(self):
        """Test /etc/sudoers is included."""
        assert "/etc/sudoers" in CRITICAL_FILES

    def test_contains_sshd_config(self):
        """Test /etc/ssh/sshd_config is included."""
        assert "/etc/ssh/sshd_config" in CRITICAL_FILES

    def test_contains_crontab(self):
        """Test /etc/crontab is included."""
        assert "/etc/crontab" in CRITICAL_FILES

    def test_all_paths_are_absolute(self):
        """Test all critical file paths are absolute."""
        for path in CRITICAL_FILES:
            assert path.startswith("/")


class TestThreatIndicatorCategories:
    """Tests for threat indicator organization."""

    def test_auth_patterns_cover_auth_events(self):
        """Test auth patterns cover key authentication events."""
        required_patterns = [
            "failed_password",
            "accepted_password",
            "accepted_key",
            "invalid_user",
            "sudo",
        ]

        for pattern in required_patterns:
            assert pattern in AUTH_PATTERNS

    def test_process_indicators_cover_attack_tools(self):
        """Test process indicators cover common attack tools."""
        attack_categories = {
            "reverse_shell": ["nc", "netcat", "ncat", "socat"],
            "credential_theft": ["mimikatz"],
            "brute_force": ["hydra", "medusa", "ncrack"],
            "crypto_mining": ["xmrig", "minerd", "cryptominer"],
        }

        for category, tools in attack_categories.items():
            for tool in tools:
                assert tool in SUSPICIOUS_PROCESS_NAMES, f"{tool} missing from {category}"

    def test_path_indicators_cover_execution_locations(self):
        """Test path indicators cover common malware execution locations."""
        common_malware_paths = ["/tmp/", "/dev/shm/", "/var/tmp/"]

        for path in common_malware_paths:
            assert path in SUSPICIOUS_PATHS

    def test_file_indicators_cover_system_critical(self):
        """Test file indicators cover system-critical files."""
        system_critical = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/group",
            "/etc/sudoers",
        ]

        for filepath in system_critical:
            assert filepath in CRITICAL_FILES
