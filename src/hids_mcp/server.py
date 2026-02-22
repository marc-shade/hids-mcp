#!/usr/bin/env python3
"""
Host-based IDS MCP Server

Host-based Intrusion Detection System for monitoring local system security.
Analyzes logs, processes, network connections, file integrity, and compliance
with federal security frameworks (NIST SP 800-53, CMMC, DISA STIG).

Compliance capabilities:
- NIST SP 800-53 Rev 5 control mapping and posture reporting
- CMMC Level 2 practice assessment
- DISA STIG automated compliance checking
- FedRAMP-ready tamper-evident audit trail (CEF/LEEF export)
- CycloneDX SBOM generation for supply chain security
"""

import hashlib
import json
import logging
import os
import re
import socket
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import psutil
from mcp.server.fastmcp import FastMCP

from hids_mcp.compliance.nist_800_53 import (
    get_compliance_report,
    map_alert_to_controls,
)
from hids_mcp.compliance.cmmc import assess_cmmc_posture
from hids_mcp.compliance.stig_checker import get_stig_summary
from hids_mcp.compliance.audit_trail import (
    AuditTrail,
    AuditEvent,
    EventType,
    EventSeverity,
    EventOutcome,
    export_to_cef,
    export_to_leef,
    get_default_trail,
)
from hids_mcp.compliance.sbom import generate_sbom_json

logger = logging.getLogger(__name__)

mcp = FastMCP("hids")

# Auth log locations
AUTH_LOGS = [
    "/var/log/auth.log",      # Debian/Ubuntu
    "/var/log/secure",        # RHEL/Fedora
    "/var/log/messages",
]

# Suspicious process indicators
SUSPICIOUS_PROCESS_NAMES = [
    "nc", "ncat", "netcat",           # Netcat variants
    "socat",                          # Socket relay
    "cryptominer", "xmrig", "minerd", # Crypto miners
    "reverse", "shell",               # Reverse shells
    "mimikatz",                       # Credential dumper
    "metasploit", "msfconsole",       # Pentesting tools
    "hydra", "medusa", "ncrack",      # Brute forcers
]

# Suspicious paths
SUSPICIOUS_PATHS = [
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
    "/run/user/",
]

# Critical files for integrity monitoring
CRITICAL_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
    "/root/.bashrc",
    "/root/.ssh/authorized_keys",
]

# Auth log patterns
AUTH_PATTERNS = {
    "failed_password": re.compile(r'Failed password for (?:invalid user )?(\S+) from (\S+)'),
    "accepted_password": re.compile(r'Accepted password for (\S+) from (\S+)'),
    "accepted_key": re.compile(r'Accepted publickey for (\S+) from (\S+)'),
    "invalid_user": re.compile(r'Invalid user (\S+) from (\S+)'),
    "sudo": re.compile(r'sudo:\s+(\S+)\s+:.*COMMAND=(.*)'),
    "session_opened": re.compile(r'session opened for user (\S+)'),
    "session_closed": re.compile(r'session closed for user (\S+)'),
    "connection_closed": re.compile(r'Connection closed by (\S+)'),
    "pam_unix": re.compile(r'pam_unix\((\S+):session\)'),
}


def get_file_hash(filepath: str) -> Optional[str]:
    """Calculate SHA256 hash of a file."""
    try:
        with open(filepath, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except (PermissionError, FileNotFoundError):
        return None


def find_auth_log() -> Optional[str]:
    """Find the auth log file for this system."""
    for log in AUTH_LOGS:
        if os.path.exists(log):
            return log
    return None


@mcp.tool()
async def analyze_auth_logs(
    log_path: Optional[str] = None,
    hours: int = 24,
    max_lines: int = 50000
) -> str:
    """
    Analyze authentication logs for security events.

    Args:
        log_path: Path to auth log (auto-detects if not specified)
        hours: Hours of logs to analyze
        max_lines: Maximum log lines to process

    Returns:
        JSON with auth log analysis
    """
    if log_path is None:
        log_path = find_auth_log()
        if log_path is None:
            return json.dumps({
                "success": False,
                "error": "No auth log found. Try specifying log_path."
            })

    if not os.path.exists(log_path):
        return json.dumps({"success": False, "error": f"Log file not found: {log_path}"})

    events = {
        "failed_logins": [],
        "successful_logins": [],
        "invalid_users": [],
        "sudo_commands": [],
        "sessions": [],
    }

    failed_by_ip = Counter()
    failed_by_user = Counter()
    successful_by_user = Counter()

    cutoff = datetime.now() - timedelta(hours=hours)

    try:
        with open(log_path, 'r', errors='ignore') as f:
            lines = f.readlines()[-max_lines:]

            for line in lines:
                # Parse timestamp (syslog format)
                try:
                    parts = line.split()
                    if len(parts) < 5:
                        continue

                    # Failed password
                    match = AUTH_PATTERNS["failed_password"].search(line)
                    if match:
                        user, ip = match.groups()
                        events["failed_logins"].append({
                            "user": user, "ip": ip, "line": line.strip()[:200]
                        })
                        failed_by_ip[ip] += 1
                        failed_by_user[user] += 1
                        continue

                    # Successful password
                    match = AUTH_PATTERNS["accepted_password"].search(line)
                    if match:
                        user, ip = match.groups()
                        events["successful_logins"].append({
                            "user": user, "ip": ip, "method": "password"
                        })
                        successful_by_user[user] += 1
                        continue

                    # Successful key auth
                    match = AUTH_PATTERNS["accepted_key"].search(line)
                    if match:
                        user, ip = match.groups()
                        events["successful_logins"].append({
                            "user": user, "ip": ip, "method": "publickey"
                        })
                        successful_by_user[user] += 1
                        continue

                    # Invalid user
                    match = AUTH_PATTERNS["invalid_user"].search(line)
                    if match:
                        user, ip = match.groups()
                        events["invalid_users"].append({"user": user, "ip": ip})
                        failed_by_ip[ip] += 1
                        continue

                    # Sudo commands
                    match = AUTH_PATTERNS["sudo"].search(line)
                    if match:
                        user, command = match.groups()
                        events["sudo_commands"].append({
                            "user": user, "command": command[:200]
                        })

                except Exception:
                    continue

    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})

    # Identify potential attacks
    alerts = []

    # Brute force detection (>10 failures from same IP)
    brute_force_ips = [ip for ip, count in failed_by_ip.items() if count >= 10]
    if brute_force_ips:
        alerts.append({
            "type": "brute_force",
            "severity": "high",
            "description": f"Brute force detected from {len(brute_force_ips)} IP(s)",
            "ips": brute_force_ips[:10]
        })

    # User enumeration (many invalid users from same IP)
    if len(events["invalid_users"]) > 20:
        alerts.append({
            "type": "user_enumeration",
            "severity": "medium",
            "description": f"{len(events['invalid_users'])} invalid user attempts detected"
        })

    return json.dumps({
        "success": True,
        "log_file": log_path,
        "time_window_hours": hours,
        "summary": {
            "failed_logins": len(events["failed_logins"]),
            "successful_logins": len(events["successful_logins"]),
            "invalid_user_attempts": len(events["invalid_users"]),
            "sudo_commands": len(events["sudo_commands"])
        },
        "top_failed_ips": dict(failed_by_ip.most_common(10)),
        "top_failed_users": dict(failed_by_user.most_common(10)),
        "successful_users": dict(successful_by_user.most_common(10)),
        "alerts": alerts,
        "recent_sudo": events["sudo_commands"][-10:],
        "recent_failures": events["failed_logins"][-10:]
    }, indent=2)


@mcp.tool()
async def detect_brute_force(
    log_path: Optional[str] = None,
    threshold: int = 5,
    window_minutes: int = 10
) -> str:
    """
    Detect brute force login attempts.

    Args:
        log_path: Path to auth log
        threshold: Failures to trigger alert
        window_minutes: Time window for detection

    Returns:
        JSON with brute force detection results
    """
    if log_path is None:
        log_path = find_auth_log()
        if log_path is None:
            return json.dumps({"success": False, "error": "No auth log found"})

    ip_attempts = defaultdict(list)

    try:
        with open(log_path, 'r', errors='ignore') as f:
            for line in f.readlines()[-20000:]:
                match = AUTH_PATTERNS["failed_password"].search(line)
                if not match:
                    match = AUTH_PATTERNS["invalid_user"].search(line)
                if match:
                    user, ip = match.groups()
                    ip_attempts[ip].append({
                        "user": user,
                        "time": datetime.now().isoformat()  # Approximate
                    })
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})

    attackers = []
    for ip, attempts in ip_attempts.items():
        if len(attempts) >= threshold:
            users_targeted = list(set(a["user"] for a in attempts))
            attackers.append({
                "ip": ip,
                "total_attempts": len(attempts),
                "unique_users_targeted": len(users_targeted),
                "users": users_targeted[:20],
                "severity": "critical" if len(attempts) >= threshold * 5 else "high"
            })

    attackers.sort(key=lambda x: x["total_attempts"], reverse=True)

    return json.dumps({
        "success": True,
        "attack_detected": len(attackers) > 0,
        "threshold": threshold,
        "attackers": attackers[:20],
        "total_unique_attacking_ips": len(attackers),
        "mitigation": [
            f"Block IPs: {', '.join(a['ip'] for a in attackers[:5])}",
            "Enable fail2ban if not already active",
            "Consider geo-blocking if attacks from specific regions",
            "Review SSH configuration (disable password auth if possible)"
        ] if attackers else ["No brute force detected"]
    }, indent=2)


@mcp.tool()
async def check_suspicious_processes() -> str:
    """
    Check for suspicious running processes.

    Returns:
        JSON with suspicious process analysis
    """
    suspicious = []
    all_procs = []

    for proc in psutil.process_iter(['pid', 'name', 'username', 'exe', 'cmdline', 'status']):
        try:
            info = proc.info
            name = info['name'] or ''
            exe = info['exe'] or ''
            cmdline = ' '.join(info['cmdline'] or [])
            username = info['username'] or ''

            proc_data = {
                "pid": info['pid'],
                "name": name,
                "user": username,
                "exe": exe[:100] if exe else None,
                "cmdline": cmdline[:200] if cmdline else None
            }

            reasons = []

            # Check for suspicious names
            name_lower = name.lower()
            for susp in SUSPICIOUS_PROCESS_NAMES:
                if susp in name_lower:
                    reasons.append(f"Suspicious name: {susp}")

            # Check for processes in suspicious paths
            if exe:
                for path in SUSPICIOUS_PATHS:
                    if exe.startswith(path):
                        reasons.append(f"Running from suspicious path: {path}")

            # Check for hidden process names
            if name.startswith('.'):
                reasons.append("Hidden process (name starts with .)")

            # Check for deleted executables
            if exe and "(deleted)" in exe:
                reasons.append("Executable has been deleted")

            # Check for shell spawning
            if any(sh in cmdline.lower() for sh in ['/bin/sh -c', '/bin/bash -c', 'python -c', 'perl -e']):
                if len(cmdline) > 50:  # Ignore simple commands
                    reasons.append("Shell command execution")

            if reasons:
                proc_data["reasons"] = reasons
                proc_data["severity"] = "high" if "deleted" in str(reasons) else "medium"
                suspicious.append(proc_data)

            all_procs.append(proc_data)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return json.dumps({
        "success": True,
        "total_processes": len(all_procs),
        "suspicious_count": len(suspicious),
        "suspicious_processes": suspicious,
        "risk_level": "high" if suspicious else "low",
        "recommendations": [
            f"Investigate PID {p['pid']} ({p['name']}): {p['reasons']}"
            for p in suspicious[:5]
        ] if suspicious else ["No suspicious processes detected"]
    }, indent=2)


@mcp.tool()
async def monitor_network_connections() -> str:
    """
    Monitor active network connections for suspicious activity.

    Returns:
        JSON with network connection analysis
    """
    connections = []
    suspicious = []

    for conn in psutil.net_connections(kind='inet'):
        try:
            conn_data = {
                "family": "IPv4" if conn.family == socket.AF_INET else "IPv6",
                "type": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                "status": conn.status,
                "pid": conn.pid
            }

            # Get process name
            if conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    conn_data["process"] = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    conn_data["process"] = "unknown"

            connections.append(conn_data)

            # Check for suspicious connections
            reasons = []

            if conn.raddr:
                remote_port = conn.raddr.port
                # Common C2/backdoor ports
                suspicious_ports = [4444, 5555, 6666, 7777, 8888, 1337, 31337, 12345]
                if remote_port in suspicious_ports:
                    reasons.append(f"Connection to suspicious port {remote_port}")

            # Check for reverse shell patterns (listening on high ports)
            if conn.status == 'LISTEN' and conn.laddr:
                port = conn.laddr.port
                if port > 1024 and port not in [3000, 5000, 8000, 8080, 8443]:
                    if conn_data.get("process") in SUSPICIOUS_PROCESS_NAMES:
                        reasons.append(f"Suspicious process listening on port {port}")

            if reasons:
                conn_data["reasons"] = reasons
                suspicious.append(conn_data)

        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
            continue

    # Summarize by status
    status_counts = Counter(c.get("status") for c in connections)
    established = [c for c in connections if c.get("status") == "ESTABLISHED"]

    return json.dumps({
        "success": True,
        "total_connections": len(connections),
        "connection_summary": dict(status_counts),
        "established_connections": len(established),
        "suspicious_connections": suspicious,
        "external_connections": [
            c for c in established
            if c.get("remote_addr") and not c["remote_addr"].startswith(("127.", "192.168.", "10.", "172."))
        ][:20],
        "risk_level": "high" if suspicious else "low"
    }, indent=2)


@mcp.tool()
async def check_listening_ports() -> str:
    """
    Check all listening ports and services.

    Returns:
        JSON with listening port analysis
    """
    listeners = []

    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'LISTEN':
            try:
                listener = {
                    "port": conn.laddr.port,
                    "address": conn.laddr.ip,
                    "pid": conn.pid,
                    "family": "IPv4" if conn.family == socket.AF_INET else "IPv6"
                }

                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        listener["process"] = proc.name()
                        listener["user"] = proc.username()
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        pass

                listeners.append(listener)
            except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                continue

    # Sort by port
    listeners.sort(key=lambda x: x["port"])

    # Identify unexpected listeners
    expected_ports = {22, 80, 443, 5432, 6379, 8080, 3306, 27017}  # Common services
    unexpected = [l for l in listeners if l["port"] not in expected_ports and l["port"] > 1024]

    return json.dumps({
        "success": True,
        "total_listeners": len(listeners),
        "all_listeners": listeners,
        "unexpected_listeners": unexpected,
        "port_summary": {
            "privileged_ports": len([l for l in listeners if l["port"] < 1024]),
            "high_ports": len([l for l in listeners if l["port"] >= 1024])
        },
        "recommendations": [
            f"Review service on port {l['port']} ({l.get('process', 'unknown')})"
            for l in unexpected[:5]
        ] if unexpected else ["All listeners appear expected"]
    }, indent=2)


@mcp.tool()
async def check_file_integrity(
    files: Optional[list] = None,
    baseline_path: Optional[str] = None
) -> str:
    """
    Check integrity of critical system files.

    Args:
        files: List of files to check (default: critical system files)
        baseline_path: Path to baseline hash file for comparison

    Returns:
        JSON with file integrity results
    """
    files_to_check = files or CRITICAL_FILES
    results = []
    baseline = {}

    # Load baseline if provided
    if baseline_path and os.path.exists(baseline_path):
        try:
            with open(baseline_path, 'r') as f:
                baseline = json.load(f)
        except (json.JSONDecodeError, IOError, OSError):
            pass

    for filepath in files_to_check:
        result = {
            "file": filepath,
            "exists": os.path.exists(filepath)
        }

        if result["exists"]:
            try:
                stat = os.stat(filepath)
                result["size"] = stat.st_size
                result["modified"] = datetime.fromtimestamp(stat.st_mtime).isoformat()
                result["permissions"] = oct(stat.st_mode)[-3:]

                file_hash = get_file_hash(filepath)
                result["sha256"] = file_hash

                # Compare with baseline
                if filepath in baseline:
                    if baseline[filepath] != file_hash:
                        result["status"] = "CHANGED"
                        result["baseline_hash"] = baseline[filepath]
                    else:
                        result["status"] = "OK"
                else:
                    result["status"] = "NO_BASELINE"

            except PermissionError:
                result["status"] = "ACCESS_DENIED"
            except Exception as e:
                result["status"] = f"ERROR: {e}"
        else:
            result["status"] = "MISSING"

        results.append(result)

    changed = [r for r in results if r.get("status") == "CHANGED"]
    missing = [r for r in results if r.get("status") == "MISSING"]

    return json.dumps({
        "success": True,
        "files_checked": len(results),
        "changed_files": len(changed),
        "missing_files": len(missing),
        "results": results,
        "alerts": [
            {"type": "file_changed", "file": r["file"], "severity": "high"}
            for r in changed
        ] + [
            {"type": "file_missing", "file": r["file"], "severity": "medium"}
            for r in missing
        ],
        "baseline_used": baseline_path is not None,
        "current_hashes": {r["file"]: r.get("sha256") for r in results if r.get("sha256")}
    }, indent=2)


@mcp.tool()
async def generate_security_report() -> str:
    """
    Generate comprehensive host security report.

    Returns:
        JSON with complete security assessment
    """
    report = {
        "success": True,
        "report_time": datetime.now().isoformat(),
        "hostname": socket.gethostname(),
        "sections": [],
        "overall_risk": "low",
        "alerts": []
    }

    # Auth log analysis
    auth_result = json.loads(await analyze_auth_logs(hours=24))
    if auth_result["success"]:
        report["sections"].append({
            "name": "Authentication",
            "summary": auth_result.get("summary", {}),
            "alerts": auth_result.get("alerts", [])
        })
        report["alerts"].extend(auth_result.get("alerts", []))

    # Process check
    proc_result = json.loads(await check_suspicious_processes())
    if proc_result["success"]:
        report["sections"].append({
            "name": "Processes",
            "total": proc_result["total_processes"],
            "suspicious": proc_result["suspicious_count"],
            "risk_level": proc_result["risk_level"]
        })
        if proc_result["suspicious_count"] > 0:
            report["alerts"].append({
                "type": "suspicious_processes",
                "severity": "high",
                "count": proc_result["suspicious_count"]
            })

    # Network connections
    net_result = json.loads(await monitor_network_connections())
    if net_result["success"]:
        report["sections"].append({
            "name": "Network",
            "total_connections": net_result["total_connections"],
            "established": net_result["established_connections"],
            "suspicious": len(net_result.get("suspicious_connections", []))
        })

    # Listening ports
    ports_result = json.loads(await check_listening_ports())
    if ports_result["success"]:
        report["sections"].append({
            "name": "Listening Services",
            "total": ports_result["total_listeners"],
            "unexpected": len(ports_result.get("unexpected_listeners", []))
        })

    # File integrity
    file_result = json.loads(await check_file_integrity())
    if file_result["success"]:
        report["sections"].append({
            "name": "File Integrity",
            "checked": file_result["files_checked"],
            "changed": file_result["changed_files"],
            "missing": file_result["missing_files"]
        })

    # Calculate overall risk
    high_alerts = [a for a in report["alerts"] if a.get("severity") == "high"]
    medium_alerts = [a for a in report["alerts"] if a.get("severity") == "medium"]

    if high_alerts:
        report["overall_risk"] = "high"
    elif medium_alerts:
        report["overall_risk"] = "medium"

    report["alert_summary"] = {
        "total": len(report["alerts"]),
        "high": len(high_alerts),
        "medium": len(medium_alerts)
    }

    return json.dumps(report, indent=2)


# =============================================================================
# Compliance & Defense Standards Tools
# =============================================================================


@mcp.tool()
async def hids_compliance_report() -> str:
    """
    Generate NIST SP 800-53 Rev 5 compliance posture report.

    Maps all HIDS capabilities to specific NIST 800-53 controls across
    families: AU (Audit), SI (System Integrity), IR (Incident Response),
    CM (Configuration Management), AC (Access Control), SC (System/Comms
    Protection), SA (System Acquisition), RA (Risk Assessment).

    Returns:
        JSON with compliance posture including:
        - Overall compliance score and rating
        - Per-family breakdown with control details
        - Enhancement coverage inventory
        - Assessment readiness metrics
        - Gap analysis for partially implemented controls
    """
    try:
        report = get_compliance_report()

        # Record compliance assessment in audit trail
        trail = get_default_trail()
        trail.record(AuditEvent(
            event_type=EventType.COMPLIANCE_CHECK,
            severity=EventSeverity.INFO,
            action="nist_800_53_compliance_report",
            outcome=EventOutcome.SUCCESS,
            description=f"NIST 800-53 compliance report generated: score={report['overall_posture']['compliance_score']}%",
            nist_controls=["AU-6", "CM-6"],
            cmmc_practices=["AU.L2-3.3.5"],
        ))

        return json.dumps(report, indent=2)
    except Exception as e:
        logger.error("Failed to generate NIST compliance report: %s", str(e))
        return json.dumps({
            "success": False,
            "error": f"Compliance report generation failed: {str(e)}"
        })


@mcp.tool()
async def hids_cmmc_assessment() -> str:
    """
    Run CMMC Level 2 compliance assessment.

    Evaluates all HIDS capabilities against CMMC Level 2 practices
    aligned with NIST SP 800-171 Rev 2 requirements for protecting
    Controlled Unclassified Information (CUI).

    Covers domains: AC (Access Control), AU (Audit & Accountability),
    CM (Configuration Management), IR (Incident Response),
    RA (Risk Assessment), SC (System & Communications Protection),
    SI (System & Information Integrity).

    Returns:
        JSON with CMMC assessment including:
        - Overall Level 2 readiness score and rating
        - Per-domain practice breakdown
        - NIST 800-171 cross-reference mapping
        - Evidence artifact inventory
        - Gap analysis with remediation guidance
        - Assessment recommendation
    """
    try:
        assessment = assess_cmmc_posture()

        trail = get_default_trail()
        trail.record(AuditEvent(
            event_type=EventType.COMPLIANCE_CHECK,
            severity=EventSeverity.INFO,
            action="cmmc_level2_assessment",
            outcome=EventOutcome.SUCCESS,
            description=f"CMMC Level 2 assessment completed: score={assessment['overall_posture']['readiness_score']}%",
            nist_controls=["CM-6", "SA-11"],
            cmmc_practices=["AU.L2-3.3.5", "CM.L2-3.4.1"],
        ))

        return json.dumps(assessment, indent=2)
    except Exception as e:
        logger.error("Failed to generate CMMC assessment: %s", str(e))
        return json.dumps({
            "success": False,
            "error": f"CMMC assessment failed: {str(e)}"
        })


@mcp.tool()
async def hids_stig_check(stig_id: Optional[str] = None) -> str:
    """
    Run DISA STIG compliance checks.

    Executes automated compliance checks against Security Technical
    Implementation Guide requirements relevant to host-based intrusion
    detection. Checks cover file integrity monitoring, audit log protection,
    login attempt monitoring, privilege escalation detection, password
    complexity, SSH configuration, and audit service status.

    Each finding includes: STIG ID, severity (CAT I/II/III),
    status (PASS/FAIL/NOT_APPLICABLE), finding details, CCI references,
    NIST control mappings, and specific remediation guidance.

    Args:
        stig_id: Optional specific STIG ID to check (e.g., 'V-230264').
                If not provided, runs all available checks.

    Returns:
        JSON with STIG compliance results including severity breakdown,
        per-check findings, and prioritized remediation plan.
    """
    try:
        if stig_id:
            from hids_mcp.compliance.stig_checker import run_single_stig_check
            finding = run_single_stig_check(stig_id)
            if finding is None:
                return json.dumps({
                    "success": False,
                    "error": f"Unknown STIG ID: {stig_id}",
                    "available_checks": list(
                        __import__(
                            'hids_mcp.compliance.stig_checker',
                            fromlist=['STIG_CHECKS']
                        ).STIG_CHECKS.keys()
                    ),
                })
            result = finding.to_dict()
            result["success"] = True
        else:
            result = get_stig_summary()
            result["success"] = True

        trail = get_default_trail()
        trail.record(AuditEvent(
            event_type=EventType.COMPLIANCE_CHECK,
            severity=EventSeverity.INFO,
            action="stig_compliance_check",
            outcome=EventOutcome.SUCCESS,
            description=f"STIG check executed: {'single=' + stig_id if stig_id else 'full scan'}",
            nist_controls=["CM-6", "SI-7", "AU-9"],
            cmmc_practices=["CM.L2-3.4.1", "SI.L2-3.14.6"],
        ))

        return json.dumps(result, indent=2)
    except Exception as e:
        logger.error("Failed to run STIG checks: %s", str(e))
        return json.dumps({
            "success": False,
            "error": f"STIG check failed: {str(e)}"
        })


@mcp.tool()
async def hids_audit_export(
    format: str = "cef",
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    since: Optional[str] = None,
    limit: int = 100,
) -> str:
    """
    Export audit trail in SIEM-compatible formats.

    Exports the tamper-evident audit trail in industry-standard formats
    for Security Information and Event Management (SIEM) integration.

    Supported formats:
    - CEF (Common Event Format): For ArcSight and generic SIEM platforms
    - LEEF (Log Event Extended Format): For IBM QRadar

    Each exported event includes: timestamp, event type, severity, source IP,
    user identity, action, outcome, NIST control references, CMMC practice
    references, SHA-256 evidence hash, and sequence number.

    Args:
        format: Export format - 'cef' or 'leef' (default: 'cef')
        event_type: Filter by event type (authentication, file_integrity,
                   process_monitoring, network_monitoring, compliance_check,
                   configuration_change, incident, system_event, audit_system)
        severity: Minimum severity filter (critical, high, medium, low, informational)
        since: ISO 8601 timestamp - export events after this time
        limit: Maximum events to export (default: 100)

    Returns:
        SIEM-formatted audit events or JSON with integrity verification
    """
    try:
        trail = get_default_trail()

        # Build filters
        type_filter = None
        if event_type:
            try:
                type_filter = EventType(event_type)
            except ValueError:
                return json.dumps({
                    "success": False,
                    "error": f"Invalid event_type: {event_type}",
                    "valid_types": [t.value for t in EventType],
                })

        severity_filter = None
        if severity:
            try:
                severity_filter = EventSeverity(severity)
            except ValueError:
                return json.dumps({
                    "success": False,
                    "error": f"Invalid severity: {severity}",
                    "valid_severities": [s.value for s in EventSeverity],
                })

        events = trail.get_events(
            event_type=type_filter,
            severity=severity_filter,
            since=since,
            limit=limit,
        )

        if format.lower() == "cef":
            exported = export_to_cef(events)
        elif format.lower() == "leef":
            exported = export_to_leef(events)
        elif format.lower() == "json":
            exported = json.dumps([e.to_dict() for e in events], indent=2)
        else:
            return json.dumps({
                "success": False,
                "error": f"Unsupported format: {format}",
                "supported_formats": ["cef", "leef", "json"],
            })

        # Also verify chain integrity
        integrity = trail.verify_integrity()

        return json.dumps({
            "success": True,
            "format": format.lower(),
            "events_exported": len(events),
            "chain_integrity": integrity,
            "exported_data": exported,
        }, indent=2)
    except Exception as e:
        logger.error("Failed to export audit trail: %s", str(e))
        return json.dumps({
            "success": False,
            "error": f"Audit export failed: {str(e)}"
        })


@mcp.tool()
async def hids_generate_sbom(include_transitive: bool = True) -> str:
    """
    Generate CycloneDX Software Bill of Materials (SBOM).

    Produces a CycloneDX 1.5 format SBOM documenting all software
    components in the HIDS-MCP installation. Critical for supply chain
    security per Executive Order 14028 and NIST SP 800-53 CM-8.

    The SBOM includes:
    - Component name, version, and description
    - SPDX license identifiers
    - Supplier information
    - SHA-256 component hashes
    - Package URLs (purl) for universal identification
    - Dependency graph

    Args:
        include_transitive: Include transitive (indirect) dependencies
                          in addition to direct dependencies (default: True)

    Returns:
        JSON with CycloneDX 1.5 SBOM including component inventory,
        dependency graph, and metadata
    """
    try:
        sbom_json = generate_sbom_json(include_transitive=include_transitive)

        trail = get_default_trail()
        sbom_data = json.loads(sbom_json)
        component_count = len(sbom_data.get("components", []))

        trail.record(AuditEvent(
            event_type=EventType.COMPLIANCE_CHECK,
            severity=EventSeverity.INFO,
            action="sbom_generation",
            outcome=EventOutcome.SUCCESS,
            description=f"CycloneDX SBOM generated: {component_count} components",
            nist_controls=["CM-8", "SA-11"],
            cmmc_practices=["CM.L2-3.4.1"],
        ))

        return json.dumps({
            "success": True,
            "format": "CycloneDX 1.5",
            "component_count": component_count,
            "sbom": sbom_data,
        }, indent=2)
    except Exception as e:
        logger.error("Failed to generate SBOM: %s", str(e))
        return json.dumps({
            "success": False,
            "error": f"SBOM generation failed: {str(e)}"
        })


def main():
    """Run the HIDS MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
