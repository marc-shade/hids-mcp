"""
DISA STIG Compliance Checker for HIDS-MCP.

Implements automated compliance checks for Security Technical Implementation
Guide (STIG) requirements relevant to Host-based Intrusion Detection Systems.

Checks are modeled after:
- RHEL 8 STIG (V-230264 series) - File integrity monitoring
- RHEL 8 STIG (V-230398 series) - Audit log protection
- RHEL 8 STIG (V-230310 series) - Login attempt monitoring
- RHEL 8 STIG (V-230311 series) - Privilege escalation detection
- General UNIX/Linux STIG patterns for system file monitoring

Each check returns: STIG ID, severity (CAT I/II/III), status (PASS/FAIL/NOT_APPLICABLE),
finding details, and remediation guidance.

Reference: https://public.cyber.mil/stigs/
"""

import grp
import hashlib
import json
import logging
import os
import platform
import pwd
import re
import stat
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class STIGSeverity(Enum):
    """DISA STIG severity categories."""
    CAT_I = "CAT I"      # High - Directly results in loss of Confidentiality, Integrity, or Availability
    CAT_II = "CAT II"    # Medium - Could lead to degradation of measures
    CAT_III = "CAT III"  # Low - Degrades in depth and defense measures


class STIGStatus(Enum):
    """STIG check result status."""
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"
    MANUAL_REVIEW = "MANUAL_REVIEW"


@dataclass
class STIGFinding:
    """Result of a single STIG compliance check."""
    stig_id: str
    rule_title: str
    severity: STIGSeverity
    status: STIGStatus
    check_description: str
    finding_details: str
    remediation_guidance: str
    cci_refs: list[str] = field(default_factory=list)
    nist_controls: list[str] = field(default_factory=list)
    check_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON output."""
        result = asdict(self)
        result["severity"] = self.severity.value
        result["status"] = self.status.value
        return result


def _file_exists(path: str) -> bool:
    """Safely check if a file exists."""
    try:
        return os.path.exists(path)
    except OSError:
        return False


def _get_file_permissions(path: str) -> Optional[str]:
    """Get octal file permissions string."""
    try:
        st = os.stat(path)
        return oct(st.st_mode)[-4:]
    except (OSError, ValueError):
        return None


def _get_file_owner(path: str) -> Optional[str]:
    """Get file owner username."""
    try:
        st = os.stat(path)
        return pwd.getpwuid(st.st_uid).pw_name
    except (OSError, KeyError):
        return None


def _get_file_group(path: str) -> Optional[str]:
    """Get file group name."""
    try:
        st = os.stat(path)
        return grp.getgrgid(st.st_gid).gr_name
    except (OSError, KeyError):
        return None


def _read_file_safe(path: str, max_bytes: int = 1048576) -> Optional[str]:
    """Safely read a file with size limit."""
    try:
        with open(path, "r", errors="ignore") as f:
            return f.read(max_bytes)
    except (OSError, PermissionError):
        return None


def _is_linux() -> bool:
    """Check if running on Linux."""
    return platform.system() == "Linux"


# =============================================================================
# STIG Check Functions
# =============================================================================

def check_v230264_file_integrity_tool() -> STIGFinding:
    """
    V-230264: RHEL 8 must use a file integrity tool.

    The system must employ a file integrity tool to check baseline configuration
    against current system files. AIDE or a similar tool must be installed.
    """
    stig_id = "V-230264"
    rule_title = "RHEL 8 must employ a file integrity verification tool"

    aide_paths = ["/usr/sbin/aide", "/usr/bin/aide", "/sbin/aide"]
    tripwire_paths = ["/usr/sbin/tripwire", "/usr/bin/tripwire"]
    ossec_paths = ["/var/ossec/bin/ossec-control", "/usr/bin/ossec-control"]
    samhain_paths = ["/usr/local/sbin/samhain", "/usr/sbin/samhain"]

    all_tools = {
        "AIDE": aide_paths,
        "Tripwire": tripwire_paths,
        "OSSEC": ossec_paths,
        "Samhain": samhain_paths,
    }

    found_tools = []
    for tool_name, paths in all_tools.items():
        for path in paths:
            if _file_exists(path):
                found_tools.append(f"{tool_name} ({path})")

    # HIDS-MCP itself provides file integrity checking
    hids_note = (
        "HIDS-MCP provides SHA-256 file integrity checking via check_file_integrity tool "
        "with baseline comparison capability."
    )

    if found_tools:
        return STIGFinding(
            stig_id=stig_id,
            rule_title=rule_title,
            severity=STIGSeverity.CAT_I,
            status=STIGStatus.PASS,
            check_description="Verify a file integrity tool is installed (AIDE, Tripwire, OSSEC, or Samhain).",
            finding_details=f"File integrity tool(s) found: {', '.join(found_tools)}. {hids_note}",
            remediation_guidance="No action required. File integrity tool is installed.",
            cci_refs=["CCI-001744"],
            nist_controls=["SI-7", "SI-7(1)"],
        )
    else:
        return STIGFinding(
            stig_id=stig_id,
            rule_title=rule_title,
            severity=STIGSeverity.CAT_I,
            status=STIGStatus.FAIL if _is_linux() else STIGStatus.NOT_APPLICABLE,
            check_description="Verify a file integrity tool is installed (AIDE, Tripwire, OSSEC, or Samhain).",
            finding_details=(
                f"No standalone file integrity tool found in standard locations. {hids_note} "
                "For full STIG compliance, install AIDE: 'dnf install aide && aide --init'."
                if _is_linux() else
                f"Non-Linux system detected ({platform.system()}). STIG check is Linux-specific. {hids_note}"
            ),
            remediation_guidance=(
                "Install AIDE: 'dnf install aide' (RHEL/Fedora) or 'apt install aide' (Debian/Ubuntu). "
                "Initialize baseline: 'aide --init && cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz'. "
                "Schedule periodic checks: add 'aide --check' to crontab."
            ),
            cci_refs=["CCI-001744"],
            nist_controls=["SI-7", "SI-7(1)"],
        )


def check_v230265_file_integrity_baseline() -> STIGFinding:
    """
    V-230265: RHEL 8 must use a file integrity baseline.

    The file integrity tool must have a current and valid baseline
    for comparison against system files.
    """
    stig_id = "V-230265"
    rule_title = "RHEL 8 must have a file integrity baseline"

    aide_db_paths = [
        "/var/lib/aide/aide.db.gz",
        "/var/lib/aide/aide.db",
        "/etc/aide/aide.db",
    ]

    found_baseline = None
    baseline_age_days = None

    for db_path in aide_db_paths:
        if _file_exists(db_path):
            found_baseline = db_path
            try:
                mtime = os.path.getmtime(db_path)
                age = datetime.now().timestamp() - mtime
                baseline_age_days = int(age / 86400)
            except OSError:
                pass
            break

    if found_baseline:
        if baseline_age_days is not None and baseline_age_days > 30:
            return STIGFinding(
                stig_id=stig_id,
                rule_title=rule_title,
                severity=STIGSeverity.CAT_II,
                status=STIGStatus.FAIL,
                check_description="Verify the file integrity baseline is current (updated within 30 days).",
                finding_details=(
                    f"Baseline found at {found_baseline} but is {baseline_age_days} days old. "
                    "Baselines should be updated within 30 days or after approved system changes."
                ),
                remediation_guidance=(
                    f"Update the AIDE baseline: 'aide --init && "
                    f"cp /var/lib/aide/aide.db.new.gz {found_baseline}'. "
                    "Schedule regular baseline updates after approved configuration changes."
                ),
                cci_refs=["CCI-001744"],
                nist_controls=["SI-7", "SI-7(1)"],
            )
        return STIGFinding(
            stig_id=stig_id,
            rule_title=rule_title,
            severity=STIGSeverity.CAT_II,
            status=STIGStatus.PASS,
            check_description="Verify the file integrity baseline is current.",
            finding_details=(
                f"Baseline found at {found_baseline}"
                + (f", age: {baseline_age_days} days." if baseline_age_days is not None else ".")
            ),
            remediation_guidance="No action required. Baseline is current.",
            cci_refs=["CCI-001744"],
            nist_controls=["SI-7", "SI-7(1)"],
        )
    else:
        return STIGFinding(
            stig_id=stig_id,
            rule_title=rule_title,
            severity=STIGSeverity.CAT_II,
            status=STIGStatus.FAIL if _is_linux() else STIGStatus.NOT_APPLICABLE,
            check_description="Verify the file integrity baseline exists and is current.",
            finding_details=(
                "No AIDE baseline database found. "
                "HIDS-MCP supports its own JSON baseline format via check_file_integrity(baseline_path=...)."
                if _is_linux() else
                f"Non-Linux system ({platform.system()}). AIDE baseline check not applicable."
            ),
            remediation_guidance=(
                "Initialize AIDE baseline: 'aide --init && "
                "cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz'."
            ),
            cci_refs=["CCI-001744"],
            nist_controls=["SI-7", "SI-7(1)"],
        )


def check_v230398_audit_log_permissions() -> STIGFinding:
    """
    V-230398: RHEL 8 audit logs must have appropriate permissions.

    Audit logs must be owned by root and have permissions no more permissive
    than 0600 to prevent unauthorized access.
    """
    stig_id = "V-230398"
    rule_title = "RHEL 8 audit logs must have mode 0600 or less permissive"

    audit_log_paths = [
        "/var/log/audit/audit.log",
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/syslog",
        "/var/log/messages",
    ]

    findings = []
    passed_all = True
    checked_any = False

    for log_path in audit_log_paths:
        if not _file_exists(log_path):
            continue

        checked_any = True
        perms = _get_file_permissions(log_path)
        owner = _get_file_owner(log_path)

        if perms is None or owner is None:
            findings.append(f"{log_path}: Unable to read permissions (access denied)")
            continue

        perms_int = int(perms, 8)
        # Check if permissions are more permissive than 0600
        is_permissive = (perms_int & 0o077) != 0  # Any group/other permissions
        is_wrong_owner = owner != "root"

        if is_permissive or is_wrong_owner:
            passed_all = False
            issues = []
            if is_permissive:
                issues.append(f"permissions={perms} (should be 0600 or less)")
            if is_wrong_owner:
                issues.append(f"owner={owner} (should be root)")
            findings.append(f"{log_path}: {', '.join(issues)}")
        else:
            findings.append(f"{log_path}: OK (perms={perms}, owner={owner})")

    if not checked_any:
        return STIGFinding(
            stig_id=stig_id,
            rule_title=rule_title,
            severity=STIGSeverity.CAT_II,
            status=STIGStatus.NOT_APPLICABLE,
            check_description="Verify audit log files have permissions of 0600 or less and are owned by root.",
            finding_details="No audit log files found at standard locations.",
            remediation_guidance="Ensure audit logging is configured and log files exist.",
            cci_refs=["CCI-000162", "CCI-000163", "CCI-000164"],
            nist_controls=["AU-9", "AU-9(3)"],
        )

    return STIGFinding(
        stig_id=stig_id,
        rule_title=rule_title,
        severity=STIGSeverity.CAT_II,
        status=STIGStatus.PASS if passed_all else STIGStatus.FAIL,
        check_description="Verify audit log files have permissions of 0600 or less and are owned by root.",
        finding_details="\n".join(findings),
        remediation_guidance=(
            "No action required." if passed_all else
            "Fix audit log permissions:\n"
            "chmod 0600 /var/log/audit/audit.log\n"
            "chown root:root /var/log/audit/audit.log\n"
            "Repeat for all audit log files with incorrect permissions."
        ),
        cci_refs=["CCI-000162", "CCI-000163", "CCI-000164"],
        nist_controls=["AU-9", "AU-9(3)"],
    )


def check_v230399_audit_log_directory_permissions() -> STIGFinding:
    """
    V-230399: RHEL 8 audit log directory must have appropriate permissions.

    The audit log directory must be owned by root with permissions no
    more permissive than 0750.
    """
    stig_id = "V-230399"
    rule_title = "RHEL 8 audit log directory must have mode 0750 or less permissive"

    audit_dirs = ["/var/log/audit", "/var/log"]

    findings = []
    passed_all = True
    checked_any = False

    for dir_path in audit_dirs:
        if not _file_exists(dir_path):
            continue

        checked_any = True
        perms = _get_file_permissions(dir_path)
        owner = _get_file_owner(dir_path)

        if perms is None or owner is None:
            findings.append(f"{dir_path}: Unable to read permissions")
            continue

        perms_int = int(perms, 8)
        # 0750 = rwxr-x---
        is_permissive = (perms_int & 0o027) != 0  # Check group write or any other permissions
        is_wrong_owner = owner != "root"

        if is_permissive or is_wrong_owner:
            passed_all = False
            issues = []
            if is_permissive:
                issues.append(f"permissions={perms} (should be 0750 or less)")
            if is_wrong_owner:
                issues.append(f"owner={owner} (should be root)")
            findings.append(f"{dir_path}: {', '.join(issues)}")
        else:
            findings.append(f"{dir_path}: OK (perms={perms}, owner={owner})")

    if not checked_any:
        return STIGFinding(
            stig_id=stig_id,
            rule_title=rule_title,
            severity=STIGSeverity.CAT_II,
            status=STIGStatus.NOT_APPLICABLE,
            check_description="Verify audit log directories have permissions of 0750 or less.",
            finding_details="No audit log directories found.",
            remediation_guidance="Ensure audit logging directories exist.",
            cci_refs=["CCI-000162", "CCI-000163"],
            nist_controls=["AU-9"],
        )

    return STIGFinding(
        stig_id=stig_id,
        rule_title=rule_title,
        severity=STIGSeverity.CAT_II,
        status=STIGStatus.PASS if passed_all else STIGStatus.FAIL,
        check_description="Verify audit log directories have permissions of 0750 or less and are owned by root.",
        finding_details="\n".join(findings),
        remediation_guidance=(
            "No action required." if passed_all else
            "Fix audit log directory permissions:\n"
            "chmod 0750 /var/log/audit\n"
            "chown root:root /var/log/audit"
        ),
        cci_refs=["CCI-000162", "CCI-000163"],
        nist_controls=["AU-9"],
    )


def check_v230310_login_attempts_monitored() -> STIGFinding:
    """
    V-230310: RHEL 8 must monitor login attempts.

    The system must log all authentication attempts (successful and
    unsuccessful) for post-incident analysis.
    """
    stig_id = "V-230310"
    rule_title = "RHEL 8 must log all authentication events"

    auth_log_paths = [
        "/var/log/auth.log",
        "/var/log/secure",
    ]

    # Check for auth log existence
    found_log = None
    for log_path in auth_log_paths:
        if _file_exists(log_path):
            found_log = log_path
            break

    # Check PAM configuration for authentication logging
    pam_configs = [
        "/etc/pam.d/system-auth",
        "/etc/pam.d/password-auth",
        "/etc/pam.d/common-auth",
        "/etc/pam.d/sshd",
    ]

    pam_logging_found = False
    pam_details = []
    for pam_path in pam_configs:
        content = _read_file_safe(pam_path)
        if content:
            if "pam_unix" in content or "pam_faillock" in content or "pam_tally2" in content:
                pam_logging_found = True
                pam_details.append(f"{pam_path}: PAM authentication logging configured")

    # Check if auditd is tracking auth events
    audit_rules_path = "/etc/audit/audit.rules"
    audit_content = _read_file_safe(audit_rules_path)
    audit_auth_rules = False
    if audit_content:
        if "faillog" in audit_content or "lastlog" in audit_content or "tallylog" in audit_content:
            audit_auth_rules = True

    has_logging = found_log is not None or pam_logging_found or audit_auth_rules

    details = []
    if found_log:
        details.append(f"Auth log found: {found_log}")
    if pam_details:
        details.extend(pam_details)
    if audit_auth_rules:
        details.append("Audit rules include authentication event monitoring")

    details.append(
        "HIDS-MCP provides auth log analysis via analyze_auth_logs tool "
        "with brute force detection and user enumeration monitoring."
    )

    if not _is_linux():
        return STIGFinding(
            stig_id=stig_id,
            rule_title=rule_title,
            severity=STIGSeverity.CAT_II,
            status=STIGStatus.NOT_APPLICABLE,
            check_description="Verify system logs all authentication attempts.",
            finding_details=f"Non-Linux system ({platform.system()}). {details[-1]}",
            remediation_guidance="Configure authentication logging per platform-specific guidance.",
            cci_refs=["CCI-000067", "CCI-000172"],
            nist_controls=["AC-17(1)", "AU-12"],
        )

    return STIGFinding(
        stig_id=stig_id,
        rule_title=rule_title,
        severity=STIGSeverity.CAT_II,
        status=STIGStatus.PASS if has_logging else STIGStatus.FAIL,
        check_description="Verify system logs all authentication attempts (successful and failed).",
        finding_details="\n".join(details) if details else "No authentication logging detected.",
        remediation_guidance=(
            "No action required." if has_logging else
            "Enable authentication logging:\n"
            "1. Ensure rsyslog is running: 'systemctl enable --now rsyslog'\n"
            "2. Configure PAM to log auth events in /etc/pam.d/system-auth\n"
            "3. Add audit rules: 'auditctl -w /var/log/faillog -p wa -k logins'\n"
            "4. Add audit rules: 'auditctl -w /var/log/lastlog -p wa -k logins'"
        ),
        cci_refs=["CCI-000067", "CCI-000172"],
        nist_controls=["AC-17(1)", "AU-12"],
    )


def check_v230311_privilege_escalation_monitored() -> STIGFinding:
    """
    V-230311: RHEL 8 must audit privilege escalation events.

    The system must generate audit records for privilege escalation
    events (su, sudo) for security analysis.
    """
    stig_id = "V-230311"
    rule_title = "RHEL 8 must audit privilege escalation events"

    findings = []
    has_priv_monitoring = False

    # Check auditd rules for privilege escalation monitoring
    audit_rules_paths = [
        "/etc/audit/audit.rules",
        "/etc/audit/rules.d/audit.rules",
        "/etc/audit/rules.d/50-privileged.rules",
    ]

    for rules_path in audit_rules_paths:
        content = _read_file_safe(rules_path)
        if content:
            # Check for sudo/su monitoring rules
            if re.search(r"-w\s+/usr/bin/sudo\s+-p\s+x", content):
                has_priv_monitoring = True
                findings.append(f"{rules_path}: sudo execution audit rule found")
            if re.search(r"-w\s+/bin/su\s+-p\s+x", content):
                has_priv_monitoring = True
                findings.append(f"{rules_path}: su execution audit rule found")
            if "privileged" in content.lower() or "execve" in content:
                has_priv_monitoring = True
                findings.append(f"{rules_path}: Privileged command auditing configured")

    # Check if auth logs capture sudo events
    auth_log_paths = ["/var/log/auth.log", "/var/log/secure"]
    for log_path in auth_log_paths:
        if _file_exists(log_path):
            content = _read_file_safe(log_path, max_bytes=65536)
            if content and "sudo" in content:
                has_priv_monitoring = True
                findings.append(f"{log_path}: Contains sudo event records")

    findings.append(
        "HIDS-MCP analyze_auth_logs monitors sudo commands with user attribution and command capture."
    )

    if not _is_linux():
        return STIGFinding(
            stig_id=stig_id,
            rule_title=rule_title,
            severity=STIGSeverity.CAT_II,
            status=STIGStatus.NOT_APPLICABLE,
            check_description="Verify privilege escalation events are audited.",
            finding_details=f"Non-Linux system ({platform.system()}). {findings[-1]}",
            remediation_guidance="Configure privilege escalation auditing per platform-specific guidance.",
            cci_refs=["CCI-000172"],
            nist_controls=["AU-12"],
        )

    return STIGFinding(
        stig_id=stig_id,
        rule_title=rule_title,
        severity=STIGSeverity.CAT_II,
        status=STIGStatus.PASS if has_priv_monitoring else STIGStatus.FAIL,
        check_description="Verify the system audits privilege escalation events (su, sudo).",
        finding_details="\n".join(findings) if findings else "No privilege escalation monitoring detected.",
        remediation_guidance=(
            "No action required." if has_priv_monitoring else
            "Add privilege escalation audit rules:\n"
            "echo '-w /usr/bin/sudo -p x -k privileged-priv_change' >> /etc/audit/rules.d/50-privileged.rules\n"
            "echo '-w /bin/su -p x -k privileged-priv_change' >> /etc/audit/rules.d/50-privileged.rules\n"
            "service auditd restart"
        ),
        cci_refs=["CCI-000172"],
        nist_controls=["AU-12"],
    )


def check_v230312_password_complexity() -> STIGFinding:
    """
    V-230312: RHEL 8 must enforce password complexity.

    The system must enforce password complexity by requiring at least
    one uppercase, one lowercase, one numeric, and one special character.
    """
    stig_id = "V-230312"
    rule_title = "RHEL 8 must enforce password complexity"

    pwquality_path = "/etc/security/pwquality.conf"
    content = _read_file_safe(pwquality_path)

    if not _is_linux():
        return STIGFinding(
            stig_id=stig_id,
            rule_title=rule_title,
            severity=STIGSeverity.CAT_II,
            status=STIGStatus.NOT_APPLICABLE,
            check_description="Verify password complexity requirements are enforced.",
            finding_details=f"Non-Linux system ({platform.system()}). Check not applicable.",
            remediation_guidance="Configure password complexity per platform-specific guidance.",
            cci_refs=["CCI-000192", "CCI-000193", "CCI-000194", "CCI-000205"],
            nist_controls=["IA-5(1)"],
        )

    if content is None:
        return STIGFinding(
            stig_id=stig_id,
            rule_title=rule_title,
            severity=STIGSeverity.CAT_II,
            status=STIGStatus.FAIL,
            check_description="Verify password complexity configuration in /etc/security/pwquality.conf.",
            finding_details=f"Cannot read {pwquality_path}. File may not exist or be inaccessible.",
            remediation_guidance=(
                "Install and configure pam_pwquality:\n"
                "dnf install libpwquality\n"
                "Edit /etc/security/pwquality.conf:\n"
                "  ucredit = -1\n"
                "  lcredit = -1\n"
                "  dcredit = -1\n"
                "  ocredit = -1\n"
                "  minlen = 15"
            ),
            cci_refs=["CCI-000192", "CCI-000193", "CCI-000194", "CCI-000205"],
            nist_controls=["IA-5(1)"],
        )

    # Check for required settings
    required_settings = {
        "ucredit": -1,   # At least one uppercase
        "lcredit": -1,   # At least one lowercase
        "dcredit": -1,   # At least one digit
        "ocredit": -1,   # At least one special character
    }

    findings = []
    all_met = True

    for setting, required_value in required_settings.items():
        match = re.search(rf"^\s*{setting}\s*=\s*(-?\d+)", content, re.MULTILINE)
        if match:
            actual_value = int(match.group(1))
            if actual_value > required_value:  # More negative = more strict
                all_met = False
                findings.append(f"{setting} = {actual_value} (required: {required_value} or less)")
            else:
                findings.append(f"{setting} = {actual_value} (OK)")
        else:
            all_met = False
            findings.append(f"{setting}: not configured (required: {required_value})")

    # Check minlen
    minlen_match = re.search(r"^\s*minlen\s*=\s*(\d+)", content, re.MULTILINE)
    if minlen_match:
        minlen = int(minlen_match.group(1))
        if minlen < 15:
            all_met = False
            findings.append(f"minlen = {minlen} (recommended: 15 or greater)")
        else:
            findings.append(f"minlen = {minlen} (OK)")
    else:
        all_met = False
        findings.append("minlen: not configured (recommended: 15)")

    return STIGFinding(
        stig_id=stig_id,
        rule_title=rule_title,
        severity=STIGSeverity.CAT_II,
        status=STIGStatus.PASS if all_met else STIGStatus.FAIL,
        check_description="Verify password complexity settings in /etc/security/pwquality.conf.",
        finding_details="\n".join(findings),
        remediation_guidance=(
            "No action required." if all_met else
            "Edit /etc/security/pwquality.conf and set:\n"
            "  ucredit = -1\n"
            "  lcredit = -1\n"
            "  dcredit = -1\n"
            "  ocredit = -1\n"
            "  minlen = 15"
        ),
        cci_refs=["CCI-000192", "CCI-000193", "CCI-000194", "CCI-000205"],
        nist_controls=["IA-5(1)"],
    )


def check_v230313_ssh_root_login() -> STIGFinding:
    """
    V-230313: RHEL 8 must not permit direct root login via SSH.

    SSH must be configured to deny direct root login to enforce
    individual accountability.
    """
    stig_id = "V-230313"
    rule_title = "RHEL 8 must not allow root login via SSH"

    sshd_config_paths = ["/etc/ssh/sshd_config"]
    # Include drop-in directory configs
    sshd_dropin = "/etc/ssh/sshd_config.d"
    if _file_exists(sshd_dropin):
        try:
            for f in os.listdir(sshd_dropin):
                if f.endswith(".conf"):
                    sshd_config_paths.append(os.path.join(sshd_dropin, f))
        except OSError:
            pass

    permit_root = None
    config_source = None

    for config_path in sshd_config_paths:
        content = _read_file_safe(config_path)
        if content:
            match = re.search(r"^\s*PermitRootLogin\s+(\S+)", content, re.MULTILINE | re.IGNORECASE)
            if match:
                permit_root = match.group(1).lower()
                config_source = config_path

    if not _is_linux() and permit_root is None:
        return STIGFinding(
            stig_id=stig_id,
            rule_title=rule_title,
            severity=STIGSeverity.CAT_I,
            status=STIGStatus.NOT_APPLICABLE,
            check_description="Verify PermitRootLogin is set to 'no' in sshd_config.",
            finding_details=f"Non-Linux system ({platform.system()}) or SSH config not found.",
            remediation_guidance="Configure SSH per platform-specific guidance.",
            cci_refs=["CCI-000770"],
            nist_controls=["IA-2(5)"],
        )

    if permit_root is None:
        return STIGFinding(
            stig_id=stig_id,
            rule_title=rule_title,
            severity=STIGSeverity.CAT_I,
            status=STIGStatus.FAIL,
            check_description="Verify PermitRootLogin is set to 'no' in sshd_config.",
            finding_details="PermitRootLogin not explicitly set in SSH configuration. Default may allow root login.",
            remediation_guidance=(
                "Add or modify in /etc/ssh/sshd_config:\n"
                "  PermitRootLogin no\n"
                "Then restart sshd: 'systemctl restart sshd'"
            ),
            cci_refs=["CCI-000770"],
            nist_controls=["IA-2(5)"],
        )

    is_secure = permit_root in ("no", "forced-commands-only")

    return STIGFinding(
        stig_id=stig_id,
        rule_title=rule_title,
        severity=STIGSeverity.CAT_I,
        status=STIGStatus.PASS if is_secure else STIGStatus.FAIL,
        check_description="Verify PermitRootLogin is set to 'no' in sshd_config.",
        finding_details=f"PermitRootLogin = {permit_root} (source: {config_source})",
        remediation_guidance=(
            "No action required." if is_secure else
            "Set in /etc/ssh/sshd_config:\n"
            "  PermitRootLogin no\n"
            "Then restart sshd: 'systemctl restart sshd'"
        ),
        cci_refs=["CCI-000770"],
        nist_controls=["IA-2(5)"],
    )


def check_v230383_critical_file_permissions() -> STIGFinding:
    """
    V-230383: RHEL 8 /etc/passwd must have appropriate permissions.

    Critical system files must have restrictive permissions to prevent
    unauthorized modification.
    """
    stig_id = "V-230383"
    rule_title = "RHEL 8 critical system files must have correct permissions"

    # File -> (max_permissions_octal, expected_owner, expected_group)
    critical_files = {
        "/etc/passwd": ("0644", "root", "root"),
        "/etc/shadow": ("0000", "root", "root"),
        "/etc/group": ("0644", "root", "root"),
        "/etc/gshadow": ("0000", "root", "root"),
        "/etc/sudoers": ("0440", "root", "root"),
    }

    findings = []
    passed_all = True
    checked_any = False

    for filepath, (max_perms, expected_owner, expected_group) in critical_files.items():
        if not _file_exists(filepath):
            continue

        checked_any = True
        actual_perms = _get_file_permissions(filepath)
        actual_owner = _get_file_owner(filepath)
        actual_group = _get_file_group(filepath)

        issues = []
        if actual_perms is not None:
            actual_int = int(actual_perms, 8)
            max_int = int(max_perms, 8)
            if actual_int > max_int:
                issues.append(f"permissions={actual_perms} (max: {max_perms})")
                passed_all = False
        if actual_owner and actual_owner != expected_owner:
            issues.append(f"owner={actual_owner} (expected: {expected_owner})")
            passed_all = False
        if actual_group and actual_group != expected_group:
            issues.append(f"group={actual_group} (expected: {expected_group})")
            passed_all = False

        if issues:
            findings.append(f"{filepath}: FAIL - {', '.join(issues)}")
        else:
            findings.append(f"{filepath}: OK (perms={actual_perms}, owner={actual_owner})")

    if not checked_any:
        return STIGFinding(
            stig_id=stig_id,
            rule_title=rule_title,
            severity=STIGSeverity.CAT_I,
            status=STIGStatus.NOT_APPLICABLE,
            check_description="Verify critical system files have correct permissions and ownership.",
            finding_details="No critical system files found at standard paths.",
            remediation_guidance="Verify system file locations for this platform.",
            cci_refs=["CCI-002165"],
            nist_controls=["AC-3(4)"],
        )

    return STIGFinding(
        stig_id=stig_id,
        rule_title=rule_title,
        severity=STIGSeverity.CAT_I,
        status=STIGStatus.PASS if passed_all else STIGStatus.FAIL,
        check_description="Verify critical system files have correct permissions and ownership.",
        finding_details="\n".join(findings),
        remediation_guidance=(
            "No action required." if passed_all else
            "Fix critical file permissions:\n"
            "chmod 0644 /etc/passwd /etc/group\n"
            "chmod 0000 /etc/shadow /etc/gshadow\n"
            "chmod 0440 /etc/sudoers\n"
            "chown root:root /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers"
        ),
        cci_refs=["CCI-002165"],
        nist_controls=["AC-3(4)"],
    )


def check_v230266_system_file_modification_alerts() -> STIGFinding:
    """
    V-230266: RHEL 8 must alert on system file modifications.

    The system must notify the system administrator when changes to
    baseline configuration are detected.
    """
    stig_id = "V-230266"
    rule_title = "RHEL 8 must generate alerts on system file modifications"

    # Check for AIDE cron job
    cron_paths = [
        "/etc/cron.daily/aide",
        "/etc/cron.d/aide",
        "/var/spool/cron/root",
        "/var/spool/cron/crontabs/root",
    ]

    aide_cron_found = False
    aide_cron_details = []

    for cron_path in cron_paths:
        content = _read_file_safe(cron_path)
        if content and "aide" in content.lower():
            aide_cron_found = True
            aide_cron_details.append(f"{cron_path}: AIDE check scheduled")

    # Check for systemd timer
    systemd_timer_paths = [
        "/etc/systemd/system/aide-check.timer",
        "/usr/lib/systemd/system/aidecheck.timer",
    ]
    for timer_path in systemd_timer_paths:
        if _file_exists(timer_path):
            aide_cron_found = True
            aide_cron_details.append(f"{timer_path}: AIDE systemd timer configured")

    hids_note = (
        "HIDS-MCP provides on-demand file integrity monitoring via check_file_integrity "
        "with alert generation for changed and missing files."
    )

    if not _is_linux():
        return STIGFinding(
            stig_id=stig_id,
            rule_title=rule_title,
            severity=STIGSeverity.CAT_II,
            status=STIGStatus.NOT_APPLICABLE,
            check_description="Verify system file modification alerts are configured.",
            finding_details=f"Non-Linux system ({platform.system()}). {hids_note}",
            remediation_guidance="Configure file modification alerting per platform-specific guidance.",
            cci_refs=["CCI-001744"],
            nist_controls=["SI-7", "SI-7(1)"],
        )

    return STIGFinding(
        stig_id=stig_id,
        rule_title=rule_title,
        severity=STIGSeverity.CAT_II,
        status=STIGStatus.PASS if aide_cron_found else STIGStatus.FAIL,
        check_description="Verify scheduled file integrity checks with alerting are configured.",
        finding_details=(
            ("\n".join(aide_cron_details) + f"\n{hids_note}")
            if aide_cron_found else
            f"No scheduled AIDE checks found. {hids_note}"
        ),
        remediation_guidance=(
            "No action required." if aide_cron_found else
            "Configure scheduled AIDE checks:\n"
            "echo '0 5 * * * /usr/sbin/aide --check | /bin/mail -s \"AIDE Report\" root' > /etc/cron.daily/aide\n"
            "chmod 755 /etc/cron.daily/aide"
        ),
        cci_refs=["CCI-001744"],
        nist_controls=["SI-7", "SI-7(1)"],
    )


def check_v230478_auditd_running() -> STIGFinding:
    """
    V-230478: RHEL 8 must have the audit service running.

    The auditd service must be active to collect security-relevant events.
    """
    stig_id = "V-230478"
    rule_title = "RHEL 8 audit service must be running"

    if not _is_linux():
        return STIGFinding(
            stig_id=stig_id,
            rule_title=rule_title,
            severity=STIGSeverity.CAT_II,
            status=STIGStatus.NOT_APPLICABLE,
            check_description="Verify the auditd service is active.",
            finding_details=f"Non-Linux system ({platform.system()}). auditd check not applicable.",
            remediation_guidance="Configure platform-appropriate audit service.",
            cci_refs=["CCI-000169"],
            nist_controls=["AU-12"],
        )

    # Check if auditd is running via /proc
    auditd_running = False
    try:
        import psutil
        for proc in psutil.process_iter(["name"]):
            if proc.info["name"] == "auditd":
                auditd_running = True
                break
    except (ImportError, Exception):
        # Fallback: check pidfile
        auditd_pid_paths = ["/var/run/auditd.pid", "/run/auditd.pid"]
        for pid_path in auditd_pid_paths:
            if _file_exists(pid_path):
                auditd_running = True
                break

    return STIGFinding(
        stig_id=stig_id,
        rule_title=rule_title,
        severity=STIGSeverity.CAT_II,
        status=STIGStatus.PASS if auditd_running else STIGStatus.FAIL,
        check_description="Verify the auditd service is active and running.",
        finding_details=(
            "auditd is running." if auditd_running else
            "auditd does not appear to be running."
        ),
        remediation_guidance=(
            "No action required." if auditd_running else
            "Enable and start auditd:\n"
            "systemctl enable auditd\n"
            "systemctl start auditd"
        ),
        cci_refs=["CCI-000169"],
        nist_controls=["AU-12"],
    )


# Registry of all STIG checks
STIG_CHECKS = {
    "V-230264": check_v230264_file_integrity_tool,
    "V-230265": check_v230265_file_integrity_baseline,
    "V-230266": check_v230266_system_file_modification_alerts,
    "V-230310": check_v230310_login_attempts_monitored,
    "V-230311": check_v230311_privilege_escalation_monitored,
    "V-230312": check_v230312_password_complexity,
    "V-230313": check_v230313_ssh_root_login,
    "V-230383": check_v230383_critical_file_permissions,
    "V-230398": check_v230398_audit_log_permissions,
    "V-230399": check_v230399_audit_log_directory_permissions,
    "V-230478": check_v230478_auditd_running,
}


def run_single_stig_check(stig_id: str) -> Optional[STIGFinding]:
    """
    Run a single STIG compliance check by ID.

    Args:
        stig_id: STIG vulnerability ID (e.g., 'V-230264')

    Returns:
        STIGFinding with results, or None if ID not found
    """
    check_func = STIG_CHECKS.get(stig_id)
    if check_func is None:
        logger.warning("Unknown STIG ID: %s", stig_id)
        return None

    try:
        result = check_func()
        logger.info(
            "STIG check %s: %s (%s)",
            stig_id,
            result.status.value,
            result.severity.value,
        )
        return result
    except Exception as e:
        logger.error("Error running STIG check %s: %s", stig_id, str(e))
        return STIGFinding(
            stig_id=stig_id,
            rule_title=STIG_CHECKS.get(stig_id, lambda: None).__doc__ or "Unknown",
            severity=STIGSeverity.CAT_II,
            status=STIGStatus.ERROR,
            check_description=f"STIG check {stig_id}",
            finding_details=f"Error executing check: {str(e)}",
            remediation_guidance="Resolve the error and re-run the check.",
        )


def run_stig_checks() -> list[STIGFinding]:
    """
    Run all STIG compliance checks.

    Returns:
        List of STIGFinding instances for all checks
    """
    results = []
    for stig_id in sorted(STIG_CHECKS.keys()):
        finding = run_single_stig_check(stig_id)
        if finding:
            results.append(finding)
    return results


def get_stig_summary() -> dict:
    """
    Generate a summary report of all STIG checks.

    Returns:
        Dictionary with overall STIG compliance summary including
        pass/fail counts, severity distribution, and findings
    """
    findings = run_stig_checks()

    total = len(findings)
    passed = [f for f in findings if f.status == STIGStatus.PASS]
    failed = [f for f in findings if f.status == STIGStatus.FAIL]
    na = [f for f in findings if f.status == STIGStatus.NOT_APPLICABLE]
    errors = [f for f in findings if f.status == STIGStatus.ERROR]

    # Severity distribution of failures
    cat_i_fails = [f for f in failed if f.severity == STIGSeverity.CAT_I]
    cat_ii_fails = [f for f in failed if f.severity == STIGSeverity.CAT_II]
    cat_iii_fails = [f for f in failed if f.severity == STIGSeverity.CAT_III]

    # Calculate compliance percentage (excluding N/A)
    applicable = total - len(na)
    compliance_pct = (len(passed) / applicable * 100) if applicable > 0 else 0.0

    report_time = datetime.now(timezone.utc).isoformat()
    report_content = json.dumps({
        "report_time": report_time,
        "total_checks": total,
        "compliance_pct": compliance_pct,
    }, sort_keys=True)
    report_hash = hashlib.sha256(report_content.encode()).hexdigest()

    return {
        "report_type": "DISA STIG Compliance Summary",
        "report_time": report_time,
        "report_hash": report_hash,
        "platform": platform.system(),
        "hostname": platform.node(),
        "overall": {
            "total_checks": total,
            "passed": len(passed),
            "failed": len(failed),
            "not_applicable": len(na),
            "errors": len(errors),
            "compliance_percentage": round(compliance_pct, 1),
        },
        "severity_breakdown": {
            "cat_i_failures": len(cat_i_fails),
            "cat_ii_failures": len(cat_ii_fails),
            "cat_iii_failures": len(cat_iii_fails),
        },
        "cat_i_findings": [f.to_dict() for f in cat_i_fails],
        "cat_ii_findings": [f.to_dict() for f in cat_ii_fails],
        "cat_iii_findings": [f.to_dict() for f in cat_iii_fails],
        "all_findings": [f.to_dict() for f in findings],
        "remediation_priority": (
            [
                {
                    "stig_id": f.stig_id,
                    "severity": f.severity.value,
                    "rule_title": f.rule_title,
                    "remediation": f.remediation_guidance,
                }
                for f in (cat_i_fails + cat_ii_fails + cat_iii_fails)
            ]
        ),
    }
