"""
NIST SP 800-53 Rev 5 Control Mapping for HIDS-MCP.

Maps Host-based Intrusion Detection System capabilities to specific
NIST SP 800-53 Rev 5 security controls. Covers control families:
- AU (Audit and Accountability)
- SI (System and Information Integrity)
- IR (Incident Response)
- CM (Configuration Management)
- AC (Access Control)
- SA (System and Services Acquisition)
- SC (System and Communications Protection)
- RA (Risk Assessment)

Reference: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
"""

import hashlib
import json
import logging
import os
import shutil
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class ControlFamily(Enum):
    """NIST 800-53 control families relevant to HIDS operations."""
    AC = "Access Control"
    AU = "Audit and Accountability"
    CM = "Configuration Management"
    IR = "Incident Response"
    RA = "Risk Assessment"
    SA = "System and Services Acquisition"
    SC = "System and Communications Protection"
    SI = "System and Information Integrity"


class ImplementationStatus(Enum):
    """Implementation status of a control."""
    IMPLEMENTED = "implemented"
    PARTIALLY_IMPLEMENTED = "partially_implemented"
    PLANNED = "planned"
    NOT_APPLICABLE = "not_applicable"
    NOT_ASSESSED = "not_assessed"


@dataclass
class ControlMapping:
    """Maps an HIDS capability to a NIST 800-53 control."""
    control_id: str
    control_name: str
    family: ControlFamily
    description: str
    hids_capability: str
    how_satisfied: str
    evidence_generation: str
    implementation_status: ImplementationStatus
    enhancement_ids: list[str] = field(default_factory=list)
    assessment_procedures: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON output."""
        result = asdict(self)
        result["family"] = self.family.value
        result["implementation_status"] = self.implementation_status.value
        return result


# Complete NIST 800-53 Rev 5 control mappings for HIDS capabilities
CONTROL_MAPPINGS: list[ControlMapping] = [
    # =========================================================================
    # AU - Audit and Accountability
    # =========================================================================
    ControlMapping(
        control_id="AU-2",
        control_name="Event Logging",
        family=ControlFamily.AU,
        description="The information system generates audit records containing information that establishes what type of event occurred, when it occurred, where it occurred, the source of the event, the outcome of the event, and the identity of any individuals, subjects, or objects/entities associated with the event.",
        hids_capability="analyze_auth_logs",
        how_satisfied="HIDS analyzes authentication logs including sshd, PAM, and sudo events. Captures login attempts (successful and failed), user identity, source IP, authentication method, and timestamps. Processes /var/log/auth.log (Debian/Ubuntu) and /var/log/secure (RHEL/Fedora).",
        evidence_generation="Auth log analysis JSON report with event counts, source IPs, user identities, and temporal patterns. Export via CEF/LEEF for SIEM integration.",
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enhancement_ids=["AU-2(1)", "AU-2(3)"],
        assessment_procedures=[
            "Verify auth log parsing covers all syslog authentication events",
            "Confirm timestamp extraction with timezone normalization",
            "Validate event categorization (failed_login, accepted_login, sudo, session)",
        ],
    ),
    ControlMapping(
        control_id="AU-3",
        control_name="Content of Audit Records",
        family=ControlFamily.AU,
        description="The information system generates audit records containing information about the type of event, time of the event, location of the event, source, outcome, and identity of subjects/objects involved.",
        hids_capability="audit_trail",
        how_satisfied="FedRAMP-ready audit trail captures: UTC ISO 8601 timestamps, event_type, severity, source_ip, user_id, action, outcome, NIST control references, and CMMC practice mappings. Each record includes SHA-256 evidence hash.",
        evidence_generation="Structured audit events with full provenance chain. Tamper-evident via SHA-256 hash chaining where each entry includes the hash of its predecessor.",
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enhancement_ids=["AU-3(1)", "AU-3(2)"],
        assessment_procedures=[
            "Verify audit records include all required fields per AU-3",
            "Confirm hash chain integrity for tamper detection",
            "Validate export to CEF and LEEF formats",
        ],
    ),
    ControlMapping(
        control_id="AU-5",
        control_name="Response to Audit Logging Process Failures",
        family=ControlFamily.AU,
        description="The information system alerts designated organizational officials in the event of an audit logging process failure and takes additional defined actions.",
        hids_capability="generate_security_report",
        how_satisfied="Security report generation detects when auth logs are missing, inaccessible, or empty. Alerts are raised for log file access failures. System reports 'No auth log found' as an error condition that operators can act on.",
        evidence_generation="Error conditions in security report JSON with specific failure modes documented.",
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enhancement_ids=["AU-5(1)"],
        assessment_procedures=[
            "Verify error reporting when log files are inaccessible",
            "Confirm alert generation on audit processing failures",
        ],
    ),
    ControlMapping(
        control_id="AU-6",
        control_name="Audit Record Review, Analysis, and Reporting",
        family=ControlFamily.AU,
        description="The organization reviews and analyzes audit records for indications of inappropriate or unusual activity and reports findings.",
        hids_capability="analyze_auth_logs, detect_brute_force, generate_security_report",
        how_satisfied="Automated analysis of authentication records with pattern detection for brute force attacks, user enumeration, privilege escalation, and anomalous login patterns. Comprehensive security reports aggregate findings across all monitored subsystems.",
        evidence_generation="Structured JSON reports with alert severity ratings (critical/high/medium/low), attack pattern identification, and actionable mitigation recommendations.",
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enhancement_ids=["AU-6(1)", "AU-6(3)", "AU-6(5)", "AU-6(6)"],
        assessment_procedures=[
            "Verify automated correlation of failed login events",
            "Confirm brute force detection with configurable thresholds",
            "Validate comprehensive report aggregation across all subsystems",
        ],
    ),
    ControlMapping(
        control_id="AU-8",
        control_name="Time Stamps",
        family=ControlFamily.AU,
        description="The information system uses internal system clocks to generate time stamps for audit records.",
        hids_capability="audit_trail",
        how_satisfied="All audit events use UTC ISO 8601 timestamps generated from the system clock. Syslog timestamp parsing normalizes to consistent format for cross-event correlation.",
        evidence_generation="UTC ISO 8601 formatted timestamps on all audit events and compliance reports.",
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enhancement_ids=["AU-8(1)"],
        assessment_procedures=[
            "Verify all timestamps are UTC ISO 8601 format",
            "Confirm timestamp consistency across audit subsystems",
        ],
    ),
    ControlMapping(
        control_id="AU-9",
        control_name="Protection of Audit Information",
        family=ControlFamily.AU,
        description="The information system protects audit information and audit logging tools from unauthorized access, modification, and deletion.",
        hids_capability="audit_trail",
        how_satisfied="Tamper-evident audit logging using SHA-256 hash chain. Each log entry includes the hash of its predecessor, enabling detection of any modification, insertion, or deletion of audit records. Evidence hashes provide cryptographic proof of record integrity.",
        evidence_generation="SHA-256 hash chain with per-entry verification capability. Integrity validation function detects any chain breakage.",
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enhancement_ids=["AU-9(2)", "AU-9(3)"],
        assessment_procedures=[
            "Verify SHA-256 hash chain implementation",
            "Test tamper detection by modifying a single record",
            "Confirm integrity verification function accuracy",
        ],
    ),
    ControlMapping(
        control_id="AU-12",
        control_name="Audit Record Generation",
        family=ControlFamily.AU,
        description="The information system generates audit records for the events defined in AU-2 and includes the content specified in AU-3.",
        hids_capability="audit_trail, analyze_auth_logs",
        how_satisfied="Audit records are generated for all security-relevant events: authentication attempts, file integrity changes, suspicious process detection, network anomalies, and compliance assessment results. Records conform to AU-3 content requirements.",
        evidence_generation="Continuous audit event stream with full AU-3 compliant content. Events tagged with applicable NIST controls and CMMC practices.",
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enhancement_ids=["AU-12(1)", "AU-12(3)"],
        assessment_procedures=[
            "Verify audit generation covers all AU-2 defined event types",
            "Confirm record content meets AU-3 specifications",
            "Validate NIST and CMMC tagging on all events",
        ],
    ),

    # =========================================================================
    # SI - System and Information Integrity
    # =========================================================================
    ControlMapping(
        control_id="SI-3",
        control_name="Malicious Code Protection",
        family=ControlFamily.SI,
        description="Employ malicious code protection mechanisms at system entry and exit points to detect and eradicate malicious code.",
        hids_capability="check_suspicious_processes",
        how_satisfied="Process monitoring detects known malicious process signatures including crypto miners (xmrig, minerd), credential dumpers (mimikatz), reverse shells (nc, ncat, socat), brute force tools (hydra, medusa, ncrack), and penetration testing frameworks (metasploit). Detects processes running from suspicious paths (/tmp, /dev/shm) and deleted executables.",
        evidence_generation="Suspicious process report with PID, process name, executable path, command line, username, and specific detection reasons with severity ratings.",
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enhancement_ids=["SI-3(1)", "SI-3(2)", "SI-3(4)"],
        assessment_procedures=[
            "Verify detection of known malicious process names",
            "Confirm detection of processes in suspicious paths",
            "Test detection of deleted executable indicators",
        ],
    ),
    ControlMapping(
        control_id="SI-4",
        control_name="System Monitoring",
        family=ControlFamily.SI,
        description="Monitor the information system to detect attacks and indicators of potential attacks, unauthorized local, network, and remote connections, and identify unauthorized use.",
        hids_capability="monitor_network_connections, check_listening_ports, check_suspicious_processes, analyze_auth_logs",
        how_satisfied="Multi-vector monitoring across network connections (C2 port detection, backdoor identification), running processes (malware signatures, suspicious behaviors), authentication events (brute force, enumeration), and listening services (unauthorized ports). Covers both local and network-based attack vectors.",
        evidence_generation="Comprehensive security report aggregating all monitoring vectors with risk ratings and specific findings.",
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enhancement_ids=["SI-4(1)", "SI-4(2)", "SI-4(4)", "SI-4(5)"],
        assessment_procedures=[
            "Verify network connection monitoring for C2 indicators",
            "Confirm process monitoring for malware signatures",
            "Validate authentication event analysis",
            "Test unauthorized listening service detection",
        ],
    ),
    ControlMapping(
        control_id="SI-5",
        control_name="Security Alerts, Advisories, and Directives",
        family=ControlFamily.SI,
        description="Receive information system security alerts, advisories, and directives from designated external organizations on an ongoing basis and generate internal security alerts.",
        hids_capability="generate_security_report, detect_brute_force",
        how_satisfied="Internal alert generation based on detected security events. Alerts include severity classification (critical/high/medium/low), affected resources, and actionable mitigation steps. Brute force alerts include IP addresses, targeted accounts, and recommended countermeasures.",
        evidence_generation="Structured alerts in JSON with severity, description, affected entities, and mitigation recommendations.",
        implementation_status=ImplementationStatus.PARTIALLY_IMPLEMENTED,
        enhancement_ids=["SI-5(1)"],
        assessment_procedures=[
            "Verify alert generation with severity classification",
            "Confirm mitigation recommendations in alerts",
            "Test alert output format compatibility with SIEM systems",
        ],
    ),
    ControlMapping(
        control_id="SI-7",
        control_name="Software, Firmware, and Information Integrity",
        family=ControlFamily.SI,
        description="Employ integrity verification tools to detect unauthorized changes to software, firmware, and information.",
        hids_capability="check_file_integrity",
        how_satisfied="SHA-256 cryptographic hash verification of critical system files (/etc/passwd, /etc/shadow, /etc/group, /etc/sudoers, /etc/ssh/sshd_config, /etc/crontab, /root/.bashrc, /root/.ssh/authorized_keys). Baseline comparison detects any modification, with alerts for changed, missing, or inaccessible files. File permissions and modification timestamps tracked.",
        evidence_generation="File integrity report with current hashes, baseline comparison results, modification timestamps, and permission states. Changed and missing files flagged with high/medium severity.",
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enhancement_ids=["SI-7(1)", "SI-7(2)", "SI-7(5)", "SI-7(7)"],
        assessment_procedures=[
            "Verify SHA-256 hash computation for all critical files",
            "Confirm baseline comparison detects modifications",
            "Test detection of missing and inaccessible files",
            "Validate permission tracking",
        ],
    ),

    # =========================================================================
    # IR - Incident Response
    # =========================================================================
    ControlMapping(
        control_id="IR-4",
        control_name="Incident Handling",
        family=ControlFamily.IR,
        description="Implement an incident handling capability for incidents that includes preparation, detection and analysis, containment, eradication, and recovery.",
        hids_capability="generate_security_report, detect_brute_force",
        how_satisfied="Detection and analysis phase supported through automated multi-vector security assessment. Brute force detection with configurable thresholds supports incident identification. Security reports provide evidence for incident analysis. Mitigation recommendations support containment planning (IP blocking, fail2ban, SSH configuration hardening).",
        evidence_generation="Security reports serve as incident documentation. Brute force reports provide attacker profiling with IP, targeted accounts, attempt counts, and severity classification.",
        implementation_status=ImplementationStatus.PARTIALLY_IMPLEMENTED,
        enhancement_ids=["IR-4(1)", "IR-4(4)"],
        assessment_procedures=[
            "Verify incident detection across all monitoring vectors",
            "Confirm mitigation recommendations for containment",
            "Validate evidence generation for incident documentation",
        ],
    ),
    ControlMapping(
        control_id="IR-5",
        control_name="Incident Monitoring",
        family=ControlFamily.IR,
        description="Track and document incidents on an ongoing basis.",
        hids_capability="audit_trail, generate_security_report",
        how_satisfied="Tamper-evident audit trail provides continuous incident monitoring with cryptographic integrity. Security reports provide point-in-time incident documentation. CEF/LEEF export enables integration with enterprise SIEM for centralized incident tracking.",
        evidence_generation="Continuous audit event stream with incident-related events tagged and classified. Export formats support enterprise incident management systems.",
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enhancement_ids=["IR-5(1)"],
        assessment_procedures=[
            "Verify continuous audit trail for incident events",
            "Confirm CEF/LEEF export for SIEM integration",
            "Test incident event tagging and classification",
        ],
    ),
    ControlMapping(
        control_id="IR-6",
        control_name="Incident Reporting",
        family=ControlFamily.IR,
        description="Require personnel to report suspected incidents to the organizational incident response capability and report incidents to defined authorities.",
        hids_capability="generate_security_report, audit_trail",
        how_satisfied="Automated incident reporting through structured security reports. CEF/LEEF export enables automated forwarding to organizational SIEM and incident response teams. Reports include all required incident details: what happened, when, where, impact assessment, and recommended actions.",
        evidence_generation="Structured incident reports in JSON, CEF, and LEEF formats suitable for automated forwarding to incident response capabilities.",
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enhancement_ids=["IR-6(1)", "IR-6(3)"],
        assessment_procedures=[
            "Verify report content meets incident reporting requirements",
            "Confirm automated export capability",
            "Test report generation completeness",
        ],
    ),

    # =========================================================================
    # CM - Configuration Management
    # =========================================================================
    ControlMapping(
        control_id="CM-3",
        control_name="Configuration Change Control",
        family=ControlFamily.CM,
        description="Determine the types of changes to the information system that are configuration-controlled and track changes.",
        hids_capability="check_file_integrity",
        how_satisfied="File integrity monitoring detects unauthorized configuration changes to critical system files. Baseline comparison identifies modifications to security-relevant configuration files (/etc/sudoers, /etc/ssh/sshd_config, /etc/passwd, /etc/group). SHA-256 hashing provides cryptographic evidence of changes.",
        evidence_generation="File integrity reports with before/after hash values for changed files, modification timestamps, and permission changes.",
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enhancement_ids=["CM-3(1)", "CM-3(2)"],
        assessment_procedures=[
            "Verify detection of configuration file modifications",
            "Confirm hash-based change evidence generation",
            "Test detection across all monitored configuration files",
        ],
    ),
    ControlMapping(
        control_id="CM-6",
        control_name="Configuration Settings",
        family=ControlFamily.CM,
        description="Establish and document configuration settings for information technology products employed within the information system.",
        hids_capability="check_file_integrity, stig_checker",
        how_satisfied="STIG compliance checking validates system configuration against DISA-approved baselines. File integrity monitoring ensures configuration files remain at their approved settings. STIG checks cover SSH configuration, audit settings, login parameters, and privilege controls.",
        evidence_generation="STIG compliance reports with pass/fail status per check, finding details, and remediation guidance. File integrity baselines document approved configurations.",
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enhancement_ids=["CM-6(1)", "CM-6(2)"],
        assessment_procedures=[
            "Verify STIG checking covers required configuration items",
            "Confirm baseline documentation of approved settings",
            "Test configuration deviation detection",
        ],
    ),
    ControlMapping(
        control_id="CM-8",
        control_name="System Component Inventory",
        family=ControlFamily.CM,
        description="Develop and document an inventory of system components that accurately reflects the information system and is at a level of granularity deemed necessary for tracking and reporting.",
        hids_capability="sbom_generation",
        how_satisfied="CycloneDX SBOM generation provides a complete inventory of all software components, including dependencies, versions, licenses, and cryptographic hashes. Supports supply chain risk assessment and vulnerability tracking.",
        evidence_generation="CycloneDX 1.5 format SBOM with component inventory including name, version, license, supplier, and SHA-256 hashes.",
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enhancement_ids=["CM-8(1)", "CM-8(3)"],
        assessment_procedures=[
            "Verify SBOM includes all direct and transitive dependencies",
            "Confirm component hash verification capability",
            "Test SBOM output conformance to CycloneDX 1.5 specification",
        ],
    ),

    # =========================================================================
    # AC - Access Control
    # =========================================================================
    ControlMapping(
        control_id="AC-7",
        control_name="Unsuccessful Logon Attempts",
        family=ControlFamily.AC,
        description="Enforce a limit of consecutive invalid logon attempts by a user during a defined time-period and automatically lock the account or delay next logon attempt.",
        hids_capability="detect_brute_force, analyze_auth_logs",
        how_satisfied="Brute force detection monitors consecutive failed login attempts per source IP with configurable thresholds and time windows. Identifies both single-source and distributed brute force attacks. Provides mitigation recommendations including IP blocking and account lockout.",
        evidence_generation="Brute force detection report with per-IP attempt counts, targeted usernames, severity classification, and recommended mitigation actions.",
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enhancement_ids=["AC-7(1)", "AC-7(2)"],
        assessment_procedures=[
            "Verify configurable threshold for failed login detection",
            "Confirm per-IP tracking of failed attempts",
            "Test distributed brute force detection capability",
        ],
    ),
    ControlMapping(
        control_id="AC-17",
        control_name="Remote Access",
        family=ControlFamily.AC,
        description="Establish and document usage restrictions, configuration requirements, and implementation guidance for each type of remote access allowed.",
        hids_capability="analyze_auth_logs, monitor_network_connections, check_listening_ports",
        how_satisfied="SSH authentication monitoring tracks all remote access attempts including method (password vs. publickey), source IP, and outcome. Network connection monitoring identifies remote access sessions. Listening port analysis detects unauthorized remote access services.",
        evidence_generation="Authentication reports documenting remote access patterns, connection inventories, and listening service analysis.",
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enhancement_ids=["AC-17(1)", "AC-17(2)", "AC-17(3)"],
        assessment_procedures=[
            "Verify SSH authentication method tracking",
            "Confirm remote connection monitoring",
            "Test unauthorized remote access service detection",
        ],
    ),

    # =========================================================================
    # SC - System and Communications Protection
    # =========================================================================
    ControlMapping(
        control_id="SC-7",
        control_name="Boundary Protection",
        family=ControlFamily.SC,
        description="Monitor and control communications at the external managed interfaces to the system and at key internal managed interfaces within the system.",
        hids_capability="monitor_network_connections, check_listening_ports",
        how_satisfied="Network connection monitoring identifies all active connections including external communications. Listening port analysis provides a complete inventory of network services. Suspicious connection detection flags communications to known C2 ports and unexpected external addresses.",
        evidence_generation="Network connection inventory with external/internal classification, suspicious connection alerts, and listening service inventory.",
        implementation_status=ImplementationStatus.PARTIALLY_IMPLEMENTED,
        enhancement_ids=["SC-7(4)", "SC-7(5)"],
        assessment_procedures=[
            "Verify external connection identification and classification",
            "Confirm suspicious port detection (C2 indicators)",
            "Test listening service inventory completeness",
        ],
    ),

    # =========================================================================
    # SA - System and Services Acquisition
    # =========================================================================
    ControlMapping(
        control_id="SA-11",
        control_name="Developer Testing and Evaluation",
        family=ControlFamily.SA,
        description="Require the developer of the system to create and implement a plan for ongoing security testing.",
        hids_capability="sbom_generation, stig_checker",
        how_satisfied="SBOM generation supports software composition analysis for vulnerability identification in dependencies. STIG compliance checking provides security configuration validation. Automated test suite validates all HIDS detection capabilities.",
        evidence_generation="SBOM for dependency vulnerability analysis. STIG reports for configuration compliance. Test results for functional validation.",
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enhancement_ids=["SA-11(1)", "SA-11(2)"],
        assessment_procedures=[
            "Verify SBOM generation for composition analysis",
            "Confirm STIG compliance check execution",
            "Test automated validation suite",
        ],
    ),

    # =========================================================================
    # RA - Risk Assessment
    # =========================================================================
    ControlMapping(
        control_id="RA-5",
        control_name="Vulnerability Monitoring and Scanning",
        family=ControlFamily.RA,
        description="Monitor and scan for vulnerabilities in the information system and hosted applications and remediate discovered vulnerabilities.",
        hids_capability="check_suspicious_processes, monitor_network_connections, check_file_integrity, sbom_generation",
        how_satisfied="Multi-vector vulnerability monitoring: process scanning for known malware and exploits, network monitoring for indicators of compromise, file integrity checking for unauthorized modifications, and SBOM-based dependency vulnerability tracking.",
        evidence_generation="Security reports with risk ratings across all monitored vectors. SBOM enables cross-referencing with vulnerability databases (NVD, OSV).",
        implementation_status=ImplementationStatus.PARTIALLY_IMPLEMENTED,
        enhancement_ids=["RA-5(2)", "RA-5(5)"],
        assessment_procedures=[
            "Verify process-based vulnerability detection",
            "Confirm network-based indicator detection",
            "Test SBOM output for vulnerability database correlation",
        ],
    ),
]

# Index by control ID for fast lookup
_CONTROL_INDEX: dict[str, ControlMapping] = {m.control_id: m for m in CONTROL_MAPPINGS}

# Index by family for grouped queries
_FAMILY_INDEX: dict[str, list[ControlMapping]] = {}
for _mapping in CONTROL_MAPPINGS:
    _family_key = _mapping.family.name
    if _family_key not in _FAMILY_INDEX:
        _FAMILY_INDEX[_family_key] = []
    _FAMILY_INDEX[_family_key].append(_mapping)

# Alert type to control mapping for rapid incident correlation
_ALERT_CONTROL_MAP: dict[str, list[str]] = {
    "brute_force": ["AC-7", "AU-6", "IR-4", "SI-4"],
    "user_enumeration": ["AC-7", "AU-6", "SI-4"],
    "suspicious_processes": ["SI-3", "SI-4", "IR-4", "RA-5"],
    "file_changed": ["SI-7", "CM-3", "AU-6", "IR-4"],
    "file_missing": ["SI-7", "CM-3", "IR-4"],
    "suspicious_connection": ["SC-7", "SI-4", "IR-4", "AC-17"],
    "unauthorized_listener": ["SC-7", "SI-4", "AC-17"],
    "privilege_escalation": ["AC-7", "AU-6", "IR-4", "SI-4"],
    "audit_failure": ["AU-5", "IR-4"],
    "configuration_change": ["CM-3", "CM-6", "SI-7"],
}


def _check_capability_available(capability: str) -> ImplementationStatus:
    """
    Check whether an HIDS capability is actually available on this system
    by probing real system state.

    Capabilities that depend on log files are checked for file existence.
    Capabilities that depend on runtime modules are checked for importability.
    Capabilities that cannot be verified dynamically return NOT_ASSESSED.

    Args:
        capability: Comma-separated HIDS capability string from a control mapping.

    Returns:
        Dynamic ImplementationStatus based on actual system state.
    """
    capabilities = [c.strip() for c in capability.split(",")]
    results = []

    for cap in capabilities:
        if cap in ("analyze_auth_logs", "detect_brute_force"):
            # Check if any auth log exists and is readable
            auth_logs = ["/var/log/auth.log", "/var/log/secure", "/var/log/messages"]
            found = any(os.path.isfile(p) and os.access(p, os.R_OK) for p in auth_logs)
            results.append(found)

        elif cap == "audit_trail":
            # Check if the audit trail module is importable and functional
            try:
                from hids_mcp.compliance.audit_trail import get_default_trail
                trail = get_default_trail()
                results.append(trail is not None)
            except Exception:
                results.append(False)

        elif cap == "check_file_integrity":
            # Check if critical files exist to monitor
            critical = ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers"]
            found = any(os.path.isfile(p) for p in critical)
            results.append(found)

        elif cap == "check_suspicious_processes":
            # Check if psutil is available for process monitoring
            try:
                import psutil
                psutil.process_iter()
                results.append(True)
            except Exception:
                results.append(False)

        elif cap in ("monitor_network_connections", "check_listening_ports"):
            # Check if psutil network monitoring is available
            try:
                import psutil
                psutil.net_connections(kind='inet')
                results.append(True)
            except Exception:
                results.append(False)

        elif cap == "generate_security_report":
            # This is a composite capability; mark as available if the module loads
            results.append(True)

        elif cap == "sbom_generation":
            try:
                from importlib.metadata import distributions
                list(distributions())[:1]
                results.append(True)
            except Exception:
                results.append(False)

        elif cap == "stig_checker":
            try:
                from hids_mcp.compliance.stig_checker import get_stig_summary
                results.append(True)
            except Exception:
                results.append(False)

        else:
            # Unknown capability - cannot assess
            return ImplementationStatus.NOT_ASSESSED

    if not results:
        return ImplementationStatus.NOT_ASSESSED

    if all(results):
        return ImplementationStatus.IMPLEMENTED
    elif any(results):
        return ImplementationStatus.PARTIALLY_IMPLEMENTED
    else:
        return ImplementationStatus.NOT_ASSESSED


def _assess_control_dynamically(mapping: ControlMapping) -> ImplementationStatus:
    """
    Determine the actual implementation status of a control by checking
    whether the underlying HIDS capability is available and functional
    on this system.

    The static mapping status serves as the *maximum* possible status.
    Dynamic checking can only downgrade it (e.g., if auth logs are missing,
    an IMPLEMENTED control becomes NOT_ASSESSED).

    Args:
        mapping: The control mapping to assess.

    Returns:
        Dynamically determined ImplementationStatus.
    """
    static_status = mapping.implementation_status

    # NOT_APPLICABLE stays as-is regardless of system state
    if static_status == ImplementationStatus.NOT_APPLICABLE:
        return ImplementationStatus.NOT_APPLICABLE

    # PLANNED stays as-is - not expected to be verifiable yet
    if static_status == ImplementationStatus.PLANNED:
        return ImplementationStatus.PLANNED

    dynamic_status = _check_capability_available(mapping.hids_capability)

    # Dynamic check can only downgrade, never upgrade
    status_rank = {
        ImplementationStatus.IMPLEMENTED: 4,
        ImplementationStatus.PARTIALLY_IMPLEMENTED: 3,
        ImplementationStatus.PLANNED: 2,
        ImplementationStatus.NOT_ASSESSED: 1,
        ImplementationStatus.NOT_APPLICABLE: 0,
    }

    if status_rank.get(dynamic_status, 0) < status_rank.get(static_status, 0):
        return dynamic_status

    return static_status


def get_control_by_id(control_id: str) -> Optional[ControlMapping]:
    """
    Retrieve a specific NIST 800-53 control mapping by ID.

    Args:
        control_id: NIST control identifier (e.g., 'AU-2', 'SI-7')

    Returns:
        ControlMapping if found, None otherwise
    """
    return _CONTROL_INDEX.get(control_id)


def get_controls_by_family(family: str) -> list[ControlMapping]:
    """
    Retrieve all control mappings for a given family.

    Args:
        family: Two-letter family code (e.g., 'AU', 'SI', 'IR')

    Returns:
        List of ControlMapping instances for the family
    """
    return _FAMILY_INDEX.get(family.upper(), [])


def map_alert_to_controls(alert: dict) -> list[dict]:
    """
    Map a HIDS alert to relevant NIST 800-53 controls.

    Takes any alert generated by the HIDS (brute force detection,
    suspicious process, file integrity change, etc.) and returns
    the applicable NIST controls with full mapping details.

    Args:
        alert: Alert dictionary with at minimum a 'type' field.
               Common types: brute_force, user_enumeration,
               suspicious_processes, file_changed, file_missing,
               suspicious_connection, unauthorized_listener,
               privilege_escalation, audit_failure,
               configuration_change

    Returns:
        List of control mapping dictionaries with full details
    """
    alert_type = alert.get("type", "")
    severity = alert.get("severity", "medium")

    control_ids = _ALERT_CONTROL_MAP.get(alert_type, [])

    if not control_ids:
        logger.warning("No NIST control mapping found for alert type: %s", alert_type)
        return []

    mapped_controls = []
    for control_id in control_ids:
        mapping = _CONTROL_INDEX.get(control_id)
        if mapping:
            result = mapping.to_dict()
            result["alert_context"] = {
                "alert_type": alert_type,
                "alert_severity": severity,
                "relevance": "primary" if control_id == control_ids[0] else "supporting",
            }
            mapped_controls.append(result)

    logger.info(
        "Mapped alert type '%s' to %d NIST controls: %s",
        alert_type,
        len(mapped_controls),
        ", ".join(control_ids),
    )

    return mapped_controls


def get_compliance_report() -> dict:
    """
    Generate a comprehensive NIST SP 800-53 Rev 5 compliance posture report.

    Analyzes all control mappings and produces a structured report showing:
    - Overall compliance posture percentage
    - Per-family compliance breakdown
    - Implemented vs. partially implemented vs. planned controls
    - Evidence generation capabilities
    - Assessment procedure inventory
    - Gap analysis for non-implemented controls

    Returns:
        Dictionary containing the full compliance posture report
    """
    report_time = datetime.now(timezone.utc).isoformat()

    # Dynamically assess each control against actual system state
    assessed_statuses: dict[str, ImplementationStatus] = {}
    for m in CONTROL_MAPPINGS:
        assessed_statuses[m.control_id] = _assess_control_dynamically(m)

    # Calculate implementation statistics from dynamic assessment
    total_controls = len(CONTROL_MAPPINGS)
    implemented = [m for m in CONTROL_MAPPINGS if assessed_statuses[m.control_id] == ImplementationStatus.IMPLEMENTED]
    partial = [m for m in CONTROL_MAPPINGS if assessed_statuses[m.control_id] == ImplementationStatus.PARTIALLY_IMPLEMENTED]
    planned = [m for m in CONTROL_MAPPINGS if assessed_statuses[m.control_id] == ImplementationStatus.PLANNED]
    not_applicable = [m for m in CONTROL_MAPPINGS if assessed_statuses[m.control_id] == ImplementationStatus.NOT_APPLICABLE]
    not_assessed = [m for m in CONTROL_MAPPINGS if assessed_statuses[m.control_id] == ImplementationStatus.NOT_ASSESSED]

    # Weighted compliance: implemented = 1.0, partial = 0.5, not_assessed/planned = 0.0
    applicable_controls = total_controls - len(not_applicable)
    if applicable_controls > 0:
        compliance_score = (len(implemented) + 0.5 * len(partial)) / applicable_controls
    else:
        compliance_score = 0.0

    # Per-family breakdown
    family_breakdown = {}
    for family_code, mappings in _FAMILY_INDEX.items():
        family_impl = [m for m in mappings if assessed_statuses[m.control_id] == ImplementationStatus.IMPLEMENTED]
        family_partial = [m for m in mappings if assessed_statuses[m.control_id] == ImplementationStatus.PARTIALLY_IMPLEMENTED]
        family_not_assessed = [m for m in mappings if assessed_statuses[m.control_id] == ImplementationStatus.NOT_ASSESSED]
        family_total = len(mappings)

        # Build control dicts with dynamic status override
        control_dicts = []
        for m in mappings:
            d = m.to_dict()
            d["assessed_status"] = assessed_statuses[m.control_id].value
            control_dicts.append(d)

        family_breakdown[family_code] = {
            "family_name": ControlFamily[family_code].value,
            "total_controls": family_total,
            "implemented": len(family_impl),
            "partially_implemented": len(family_partial),
            "not_assessed": len(family_not_assessed),
            "compliance_percentage": round(
                ((len(family_impl) + 0.5 * len(family_partial)) / family_total * 100)
                if family_total > 0 else 0.0,
                1,
            ),
            "controls": control_dicts,
        }

    # Enhancement coverage
    all_enhancements = []
    for m in CONTROL_MAPPINGS:
        all_enhancements.extend(m.enhancement_ids)

    # Assessment procedure inventory
    total_procedures = sum(len(m.assessment_procedures) for m in CONTROL_MAPPINGS)

    # Generate report hash for integrity
    report_content = json.dumps({
        "report_time": report_time,
        "total_controls": total_controls,
        "compliance_score": compliance_score,
    }, sort_keys=True)
    report_hash = hashlib.sha256(report_content.encode()).hexdigest()

    report = {
        "report_type": "NIST SP 800-53 Rev 5 Compliance Posture",
        "report_time": report_time,
        "report_hash": report_hash,
        "framework_version": "NIST SP 800-53 Rev 5",
        "system_name": "HIDS-MCP (Host-based Intrusion Detection System)",
        "overall_posture": {
            "compliance_score": round(compliance_score * 100, 1),
            "compliance_rating": _score_to_rating(compliance_score),
            "total_controls_mapped": total_controls,
            "implemented": len(implemented),
            "partially_implemented": len(partial),
            "planned": len(planned),
            "not_applicable": len(not_applicable),
            "not_assessed": len(not_assessed),
            "dynamically_verified": True,
        },
        "family_breakdown": family_breakdown,
        "enhancement_coverage": {
            "total_enhancements_addressed": len(all_enhancements),
            "unique_enhancements": len(set(all_enhancements)),
            "enhancements_list": sorted(set(all_enhancements)),
        },
        "assessment_readiness": {
            "total_assessment_procedures": total_procedures,
            "evidence_generation_capabilities": [
                m.evidence_generation for m in CONTROL_MAPPINGS
            ],
        },
        "gap_analysis": {
            "partially_implemented_controls": [
                {
                    "control_id": m.control_id,
                    "control_name": m.control_name,
                    "gap_description": "Requires additional implementation to achieve full compliance",
                    "hids_capability": m.hids_capability,
                }
                for m in partial
            ],
            "planned_controls": [
                {
                    "control_id": m.control_id,
                    "control_name": m.control_name,
                    "hids_capability": m.hids_capability,
                }
                for m in planned
            ],
            "not_assessed_controls": [
                {
                    "control_id": m.control_id,
                    "control_name": m.control_name,
                    "reason": "Capability could not be dynamically verified on this system",
                    "hids_capability": m.hids_capability,
                    "static_status": m.implementation_status.value,
                }
                for m in not_assessed
            ],
        },
    }

    logger.info(
        "Generated NIST 800-53 compliance report: score=%.1f%%, controls=%d, hash=%s",
        compliance_score * 100,
        total_controls,
        report_hash[:16],
    )

    return report


def _score_to_rating(score: float) -> str:
    """Convert a numeric compliance score to a qualitative rating."""
    if score >= 0.9:
        return "Excellent"
    elif score >= 0.75:
        return "Good"
    elif score >= 0.5:
        return "Moderate"
    elif score >= 0.25:
        return "Low"
    else:
        return "Critical"
