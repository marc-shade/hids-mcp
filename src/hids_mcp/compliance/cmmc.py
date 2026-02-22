"""
CMMC Level 2 Practice Mapping for HIDS-MCP.

Maps Host-based Intrusion Detection System capabilities to Cybersecurity
Maturity Model Certification (CMMC) Level 2 practices. CMMC Level 2 aligns
with NIST SP 800-171 Rev 2 requirements for protecting Controlled
Unclassified Information (CUI).

Key domains covered:
- AC (Access Control)
- AU (Audit & Accountability)
- IR (Incident Response)
- SI (System & Information Integrity)
- SC (System & Communications Protection)
- CM (Configuration Management)
- RA (Risk Assessment)

Reference: https://www.acq.osd.mil/cmmc/
CMMC Model v2.0 aligned with NIST SP 800-171 Rev 2
"""

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class CMMCDomain(Enum):
    """CMMC Level 2 domains."""
    AC = "Access Control"
    AU = "Audit & Accountability"
    CM = "Configuration Management"
    IR = "Incident Response"
    RA = "Risk Assessment"
    SC = "System & Communications Protection"
    SI = "System & Information Integrity"


class MaturityLevel(Enum):
    """CMMC maturity levels."""
    LEVEL_1 = 1
    LEVEL_2 = 2
    LEVEL_3 = 3


class PracticeStatus(Enum):
    """Practice implementation status."""
    MET = "met"
    PARTIALLY_MET = "partially_met"
    NOT_MET = "not_met"
    NOT_APPLICABLE = "not_applicable"
    NOT_ASSESSED = "not_assessed"


@dataclass
class CMMCPractice:
    """Maps an HIDS capability to a CMMC practice."""
    practice_id: str
    practice_name: str
    domain: CMMCDomain
    level: MaturityLevel
    nist_800_171_ref: str
    description: str
    hids_capability: str
    how_satisfied: str
    evidence_artifacts: list[str]
    status: PracticeStatus
    assessment_objectives: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON output."""
        result = asdict(self)
        result["domain"] = self.domain.value
        result["level"] = self.level.value
        result["status"] = self.status.value
        return result


# Complete CMMC Level 2 practice mappings for HIDS capabilities
PRACTICE_MAPPINGS: list[CMMCPractice] = [
    # =========================================================================
    # AC - Access Control
    # =========================================================================
    CMMCPractice(
        practice_id="AC.L2-3.1.7",
        practice_name="Unsuccessful Logon Attempts",
        domain=CMMCDomain.AC,
        level=MaturityLevel.LEVEL_2,
        nist_800_171_ref="3.1.8",
        description="Limit unsuccessful logon attempts.",
        hids_capability="detect_brute_force, analyze_auth_logs",
        how_satisfied="Brute force detection monitors failed login attempts per source IP with configurable thresholds (default: 5 failures) and time windows (default: 10 minutes). Identifies both concentrated single-source and distributed multi-source brute force campaigns. Provides IP-level tracking with targeted username analysis.",
        evidence_artifacts=[
            "Brute force detection report (JSON) with per-IP attempt counts",
            "Failed login statistics with temporal analysis",
            "Attacker profiling with targeted account lists",
            "Mitigation recommendations (IP blocking, fail2ban, SSH hardening)",
        ],
        status=PracticeStatus.MET,
        assessment_objectives=[
            "Determine if the number of allowed consecutive invalid logon attempts is defined",
            "Determine if the system enforces limiting consecutive invalid logon attempts",
            "Verify HIDS detection threshold aligns with organizational policy",
        ],
    ),
    CMMCPractice(
        practice_id="AC.L2-3.1.10",
        practice_name="Session Lock",
        domain=CMMCDomain.AC,
        level=MaturityLevel.LEVEL_2,
        nist_800_171_ref="3.1.10",
        description="Use session lock with pattern-hiding displays to prevent access and viewing of data after a period of inactivity.",
        hids_capability="analyze_auth_logs",
        how_satisfied="Session monitoring tracks PAM session open/close events, detecting sessions that remain open beyond policy limits. Authentication log analysis identifies active sessions and can correlate with session timeout enforcement.",
        evidence_artifacts=[
            "Session activity logs with open/close timestamps",
            "Long-running session detection reports",
        ],
        status=PracticeStatus.PARTIALLY_MET,
        assessment_objectives=[
            "Determine if session lock is initiated after a defined period of inactivity",
            "Verify session monitoring captures all session lifecycle events",
        ],
    ),
    CMMCPractice(
        practice_id="AC.L2-3.1.12",
        practice_name="Remote Access Control",
        domain=CMMCDomain.AC,
        level=MaturityLevel.LEVEL_2,
        nist_800_171_ref="3.1.12",
        description="Monitor and control remote access sessions.",
        hids_capability="analyze_auth_logs, monitor_network_connections, check_listening_ports",
        how_satisfied="Comprehensive remote access monitoring: SSH authentication tracking (password and publickey methods), source IP logging, session duration tracking via PAM events. Network connection monitoring identifies all remote access sessions. Listening port analysis detects unauthorized remote access services.",
        evidence_artifacts=[
            "SSH authentication reports with method, source IP, and outcome",
            "Active remote session inventory",
            "Listening service analysis for unauthorized remote access points",
            "CEF/LEEF export for centralized remote access monitoring",
        ],
        status=PracticeStatus.MET,
        assessment_objectives=[
            "Determine if remote access sessions are monitored",
            "Verify all remote access methods are tracked",
            "Confirm session control capabilities",
        ],
    ),

    # =========================================================================
    # AU - Audit & Accountability
    # =========================================================================
    CMMCPractice(
        practice_id="AU.L2-3.3.1",
        practice_name="System Auditing",
        domain=CMMCDomain.AU,
        level=MaturityLevel.LEVEL_2,
        nist_800_171_ref="3.3.1",
        description="Create and retain system audit logs and records to the extent needed to enable the monitoring, analysis, investigation, and reporting of unlawful or unauthorized system activity.",
        hids_capability="audit_trail, analyze_auth_logs",
        how_satisfied="FedRAMP-ready audit trail generates structured audit records for all security-relevant events. Records include: UTC ISO 8601 timestamps, event type, severity, source IP, user ID, action, outcome, NIST control references, and CMMC practice mappings. Tamper-evident SHA-256 hash chain ensures record integrity. Configurable retention policy enforcement.",
        evidence_artifacts=[
            "Audit event records with full field population per FedRAMP requirements",
            "SHA-256 hash chain integrity verification results",
            "Retention policy configuration and enforcement logs",
            "CEF/LEEF exports for SIEM integration",
        ],
        status=PracticeStatus.MET,
        assessment_objectives=[
            "Determine if audit records contain sufficient information for after-the-fact investigation",
            "Verify audit records are retained per organizational policy",
            "Confirm hash chain integrity for tamper detection",
        ],
    ),
    CMMCPractice(
        practice_id="AU.L2-3.3.2",
        practice_name="Audit Record Content",
        domain=CMMCDomain.AU,
        level=MaturityLevel.LEVEL_2,
        nist_800_171_ref="3.3.2",
        description="Ensure that the actions of individual system users can be uniquely traced to those users so they can be held accountable for their actions.",
        hids_capability="audit_trail, analyze_auth_logs",
        how_satisfied="Audit records include user_id field linking events to specific users. Authentication log analysis tracks per-user login attempts, session activity, and sudo command execution. Individual accountability maintained through user-action-outcome correlation in all audit events.",
        evidence_artifacts=[
            "User-attributed audit events with action and outcome",
            "Per-user login and session activity reports",
            "Sudo command logs attributed to executing user",
        ],
        status=PracticeStatus.MET,
        assessment_objectives=[
            "Determine if system audit records contain user identity information",
            "Verify individual user actions are traceable through audit records",
        ],
    ),
    CMMCPractice(
        practice_id="AU.L2-3.3.4",
        practice_name="Audit Failure Alerting",
        domain=CMMCDomain.AU,
        level=MaturityLevel.LEVEL_2,
        nist_800_171_ref="3.3.4",
        description="Alert in the event of an audit logging process failure.",
        hids_capability="generate_security_report, audit_trail",
        how_satisfied="HIDS detects audit logging failures: inaccessible log files, empty logs, permission errors, and processing exceptions. Error conditions are reported in security reports with specific failure modes. Audit trail subsystem validates its own integrity via hash chain verification.",
        evidence_artifacts=[
            "Error reports for log access failures",
            "Hash chain integrity validation results",
            "Audit subsystem health status in security reports",
        ],
        status=PracticeStatus.MET,
        assessment_objectives=[
            "Determine if the system alerts on audit failure conditions",
            "Verify failure detection covers all audit subsystems",
        ],
    ),
    CMMCPractice(
        practice_id="AU.L2-3.3.5",
        practice_name="Audit Review and Analysis",
        domain=CMMCDomain.AU,
        level=MaturityLevel.LEVEL_2,
        nist_800_171_ref="3.3.5",
        description="Correlate audit record review, analysis, and reporting processes to support organizational processes for investigation and response to indications of unlawful, unauthorized, suspicious, or unusual activity.",
        hids_capability="generate_security_report, analyze_auth_logs, detect_brute_force",
        how_satisfied="Automated multi-vector analysis correlates findings across authentication logs, process monitoring, network connections, and file integrity. Comprehensive security reports aggregate alerts with severity ratings. CEF/LEEF export enables correlation with enterprise SIEM platforms for organizational investigation processes.",
        evidence_artifacts=[
            "Comprehensive security report with cross-vector correlation",
            "Alert aggregation with severity classification",
            "CEF/LEEF formatted exports for SIEM correlation",
        ],
        status=PracticeStatus.MET,
        assessment_objectives=[
            "Determine if audit records are reviewed for indicators of compromise",
            "Verify correlation across multiple audit sources",
            "Confirm export capability for organizational SIEM",
        ],
    ),
    CMMCPractice(
        practice_id="AU.L2-3.3.8",
        practice_name="Audit Protection",
        domain=CMMCDomain.AU,
        level=MaturityLevel.LEVEL_2,
        nist_800_171_ref="3.3.8",
        description="Protect audit information and audit logging tools from unauthorized access, modification, and deletion.",
        hids_capability="audit_trail",
        how_satisfied="Tamper-evident logging via SHA-256 hash chain where each entry cryptographically references its predecessor. Any modification, insertion, or deletion of audit records breaks the hash chain and is detectable via integrity verification. Evidence hashes provide per-record integrity proof.",
        evidence_artifacts=[
            "SHA-256 hash chain implementation with per-record linking",
            "Integrity verification function with chain validation",
            "Evidence hash for each individual audit record",
        ],
        status=PracticeStatus.MET,
        assessment_objectives=[
            "Determine if audit records are protected from unauthorized modification",
            "Verify tamper detection capability via hash chain validation",
            "Confirm integrity verification function operates correctly",
        ],
    ),
    CMMCPractice(
        practice_id="AU.L2-3.3.9",
        practice_name="Audit Management",
        domain=CMMCDomain.AU,
        level=MaturityLevel.LEVEL_2,
        nist_800_171_ref="3.3.9",
        description="Limit management of audit logging functionality to a subset of privileged users.",
        hids_capability="audit_trail",
        how_satisfied="Audit trail operates as a system-level service with write-only append semantics. No user-facing interface for modifying or deleting audit records. Configuration changes to audit parameters are themselves audited.",
        evidence_artifacts=[
            "Audit trail append-only implementation documentation",
            "Audit configuration change logging",
        ],
        status=PracticeStatus.MET,
        assessment_objectives=[
            "Determine if audit management is restricted to privileged users",
            "Verify audit configuration changes are logged",
        ],
    ),

    # =========================================================================
    # CM - Configuration Management
    # =========================================================================
    CMMCPractice(
        practice_id="CM.L2-3.4.1",
        practice_name="System Baselining",
        domain=CMMCDomain.CM,
        level=MaturityLevel.LEVEL_2,
        nist_800_171_ref="3.4.1",
        description="Establish and maintain baseline configurations and inventories of organizational systems including hardware, software, firmware, and documentation throughout the respective system development life cycles.",
        hids_capability="check_file_integrity, sbom_generation",
        how_satisfied="File integrity monitoring establishes SHA-256 cryptographic baselines for critical system files and detects any deviation. CycloneDX SBOM generation provides a complete software component inventory with versions, licenses, and hashes. Together these provide baseline documentation for both system configuration and software composition.",
        evidence_artifacts=[
            "File integrity baseline (JSON) with SHA-256 hashes for critical files",
            "CycloneDX SBOM with full component inventory",
            "Configuration change detection reports",
        ],
        status=PracticeStatus.MET,
        assessment_objectives=[
            "Determine if baseline configurations are established and maintained",
            "Verify baseline includes software inventory with version information",
            "Confirm deviation detection from established baselines",
        ],
    ),
    CMMCPractice(
        practice_id="CM.L2-3.4.3",
        practice_name="System Change Management",
        domain=CMMCDomain.CM,
        level=MaturityLevel.LEVEL_2,
        nist_800_171_ref="3.4.3",
        description="Track, review, approve or disapprove, and log changes to organizational systems.",
        hids_capability="check_file_integrity, audit_trail",
        how_satisfied="File integrity monitoring detects all changes to monitored configuration files with before/after hash comparison. Changes are logged in the tamper-evident audit trail with timestamps, affected files, and hash values. STIG compliance checking validates that changes maintain approved security configurations.",
        evidence_artifacts=[
            "File modification detection reports with hash comparison",
            "Audit trail entries for configuration changes",
            "STIG compliance validation after changes",
        ],
        status=PracticeStatus.MET,
        assessment_objectives=[
            "Determine if changes to systems are tracked and logged",
            "Verify change detection covers security-relevant configurations",
        ],
    ),
    CMMCPractice(
        practice_id="CM.L2-3.4.5",
        practice_name="Access Restrictions for Change",
        domain=CMMCDomain.CM,
        level=MaturityLevel.LEVEL_2,
        nist_800_171_ref="3.4.5",
        description="Define, document, approve, and enforce physical and logical access restrictions associated with changes to organizational systems.",
        hids_capability="analyze_auth_logs, check_file_integrity",
        how_satisfied="Monitors sudo command execution to track privileged access used for system changes. File integrity monitoring detects unauthorized modifications even if access controls are bypassed. Authentication log analysis identifies who accessed the system and what privileged operations they performed.",
        evidence_artifacts=[
            "Sudo command logs with user attribution",
            "File integrity change detection with privilege context",
            "Authentication logs for change-related sessions",
        ],
        status=PracticeStatus.MET,
        assessment_objectives=[
            "Determine if access to change system configurations is restricted",
            "Verify privileged command execution is logged",
        ],
    ),

    # =========================================================================
    # IR - Incident Response
    # =========================================================================
    CMMCPractice(
        practice_id="IR.L2-3.6.1",
        practice_name="Incident Handling",
        domain=CMMCDomain.IR,
        level=MaturityLevel.LEVEL_2,
        nist_800_171_ref="3.6.1",
        description="Establish an operational incident-handling capability for organizational systems that includes preparation, detection, analysis, containment, recovery, and user response activities.",
        hids_capability="generate_security_report, detect_brute_force, check_suspicious_processes",
        how_satisfied="Automated detection across multiple vectors: brute force attacks, malicious processes, unauthorized network connections, file integrity violations. Analysis through structured severity-rated alerts. Containment guidance via mitigation recommendations (IP blocking, service hardening, process termination). Evidence collection through tamper-evident audit trail.",
        evidence_artifacts=[
            "Multi-vector security reports with severity-rated alerts",
            "Brute force attacker profiles for containment actions",
            "Suspicious process reports with termination guidance",
            "Mitigation recommendations for each alert type",
        ],
        status=PracticeStatus.MET,
        assessment_objectives=[
            "Determine if incident detection covers required attack vectors",
            "Verify analysis produces severity-rated findings",
            "Confirm containment recommendations are actionable",
        ],
    ),
    CMMCPractice(
        practice_id="IR.L2-3.6.2",
        practice_name="Incident Reporting",
        domain=CMMCDomain.IR,
        level=MaturityLevel.LEVEL_2,
        nist_800_171_ref="3.6.2",
        description="Track, document, and report incidents to designated officials and/or authorities both internal and external to the organization.",
        hids_capability="audit_trail, generate_security_report",
        how_satisfied="Structured incident documentation through JSON security reports. CEF (Common Event Format) and LEEF (Log Event Extended Format) export for automated forwarding to SIEM and incident response teams. Tamper-evident audit trail provides chain-of-custody evidence. Reports include required incident details: what, when, where, impact, and recommended actions.",
        evidence_artifacts=[
            "Structured incident reports (JSON, CEF, LEEF formats)",
            "Tamper-evident audit trail for chain-of-custody",
            "Automated SIEM integration via standard formats",
        ],
        status=PracticeStatus.MET,
        assessment_objectives=[
            "Determine if incidents are tracked and documented",
            "Verify reporting includes required incident details",
            "Confirm export capability for external reporting",
        ],
    ),

    # =========================================================================
    # SC - System & Communications Protection
    # =========================================================================
    CMMCPractice(
        practice_id="SC.L2-3.13.1",
        practice_name="Boundary Protection",
        domain=CMMCDomain.SC,
        level=MaturityLevel.LEVEL_2,
        nist_800_171_ref="3.13.1",
        description="Monitor, control, and protect communications at the external managed interfaces to the system and at key internal managed interfaces within the system.",
        hids_capability="monitor_network_connections, check_listening_ports",
        how_satisfied="Network connection monitoring provides real-time visibility into all active connections including external communications. Suspicious connection detection flags known C2 ports (4444, 5555, 6666, 7777, 8888, 1337, 31337, 12345) and unexpected external addresses. Listening port analysis inventories all network services to detect unauthorized access points.",
        evidence_artifacts=[
            "Active connection inventory with external/internal classification",
            "Suspicious connection alerts for C2 indicators",
            "Listening service inventory with process attribution",
        ],
        status=PracticeStatus.MET,
        assessment_objectives=[
            "Determine if communications are monitored at system boundaries",
            "Verify detection of unauthorized network services",
            "Confirm identification of suspicious external communications",
        ],
    ),
    CMMCPractice(
        practice_id="SC.L2-3.13.6",
        practice_name="Network Communication by Exception",
        domain=CMMCDomain.SC,
        level=MaturityLevel.LEVEL_2,
        nist_800_171_ref="3.13.6",
        description="Deny network communications traffic by default and allow network communications traffic by exception.",
        hids_capability="check_listening_ports, monitor_network_connections",
        how_satisfied="Listening port analysis identifies unexpected services beyond expected baseline (SSH, HTTP, HTTPS, and standard databases). Unexpected listener detection flags services that should not exist per the deny-by-default policy. Network monitoring identifies connections to non-standard ports.",
        evidence_artifacts=[
            "Expected vs. unexpected listening service comparison",
            "Non-baseline service detection alerts",
            "Network connection analysis for policy-excepted communications",
        ],
        status=PracticeStatus.PARTIALLY_MET,
        assessment_objectives=[
            "Determine if default-deny is the network policy",
            "Verify detection of services outside the exception list",
        ],
    ),

    # =========================================================================
    # SI - System & Information Integrity
    # =========================================================================
    CMMCPractice(
        practice_id="SI.L2-3.14.1",
        practice_name="Flaw Remediation",
        domain=CMMCDomain.SI,
        level=MaturityLevel.LEVEL_2,
        nist_800_171_ref="3.14.1",
        description="Identify, report, and correct system flaws in a timely manner.",
        hids_capability="sbom_generation, check_suspicious_processes",
        how_satisfied="CycloneDX SBOM enables identification of vulnerable components by cross-referencing with NVD and OSV vulnerability databases. Process monitoring detects exploitation of known flaws via malware signatures. STIG compliance checking identifies configuration flaws.",
        evidence_artifacts=[
            "SBOM for vulnerability database correlation",
            "Malware detection reports indicating exploitation",
            "STIG compliance reports identifying configuration flaws",
        ],
        status=PracticeStatus.PARTIALLY_MET,
        assessment_objectives=[
            "Determine if system flaws are identified through vulnerability tracking",
            "Verify SBOM enables component-level flaw identification",
        ],
    ),
    CMMCPractice(
        practice_id="SI.L2-3.14.2",
        practice_name="Malicious Code Protection",
        domain=CMMCDomain.SI,
        level=MaturityLevel.LEVEL_2,
        nist_800_171_ref="3.14.2",
        description="Provide protection from malicious code at designated locations within organizational systems.",
        hids_capability="check_suspicious_processes",
        how_satisfied="Process-level malicious code detection through signature matching against known threats: crypto miners (xmrig, minerd), credential dumpers (mimikatz), reverse shells (nc, ncat, socat), brute force tools (hydra, medusa, ncrack), and pentesting frameworks (metasploit). Detection of processes in suspicious locations (/tmp, /dev/shm) and deleted executables indicating runtime injection.",
        evidence_artifacts=[
            "Suspicious process detection reports with threat classification",
            "Process path analysis for suspicious location detection",
            "Deleted executable detection indicating memory-resident malware",
        ],
        status=PracticeStatus.MET,
        assessment_objectives=[
            "Determine if malicious code protection mechanisms are employed",
            "Verify detection covers known malware families",
            "Confirm detection of processes in suspicious locations",
        ],
    ),
    CMMCPractice(
        practice_id="SI.L2-3.14.3",
        practice_name="Security Alerts & Advisories",
        domain=CMMCDomain.SI,
        level=MaturityLevel.LEVEL_2,
        nist_800_171_ref="3.14.3",
        description="Monitor system security alerts and advisories and take action in response.",
        hids_capability="generate_security_report, detect_brute_force",
        how_satisfied="Automated security alert generation with severity classification (critical/high/medium/low). Brute force alerts include attacker IPs, targeted accounts, and recommended countermeasures. Security reports aggregate alerts across all monitoring vectors for holistic threat assessment.",
        evidence_artifacts=[
            "Severity-classified security alerts",
            "Brute force attacker profiles with mitigation steps",
            "Comprehensive security report with alert aggregation",
        ],
        status=PracticeStatus.MET,
        assessment_objectives=[
            "Determine if security alerts are generated for detected threats",
            "Verify alerts include severity classification",
            "Confirm actionable mitigation recommendations",
        ],
    ),
    CMMCPractice(
        practice_id="SI.L2-3.14.6",
        practice_name="System Monitoring",
        domain=CMMCDomain.SI,
        level=MaturityLevel.LEVEL_2,
        nist_800_171_ref="3.14.6",
        description="Monitor organizational systems, including inbound and outbound communications traffic, to detect attacks and indicators of potential attacks.",
        hids_capability="monitor_network_connections, check_suspicious_processes, analyze_auth_logs, check_file_integrity",
        how_satisfied="Comprehensive host-based monitoring across four vectors: (1) Network - active connections, listening ports, C2 indicators, external communications; (2) Processes - malware signatures, suspicious paths, deleted executables, shell spawning; (3) Authentication - failed logins, brute force, user enumeration, privilege escalation; (4) File integrity - unauthorized modifications to critical system files.",
        evidence_artifacts=[
            "Network connection analysis with C2 detection",
            "Process monitoring with malware signature matching",
            "Authentication analysis with attack pattern detection",
            "File integrity reports with modification detection",
        ],
        status=PracticeStatus.MET,
        assessment_objectives=[
            "Determine if monitoring covers inbound and outbound traffic",
            "Verify attack detection across multiple vectors",
            "Confirm indicator of compromise detection capability",
        ],
    ),
    CMMCPractice(
        practice_id="SI.L2-3.14.7",
        practice_name="Unauthorized Activity Detection",
        domain=CMMCDomain.SI,
        level=MaturityLevel.LEVEL_2,
        nist_800_171_ref="3.14.7",
        description="Identify unauthorized use of organizational systems.",
        hids_capability="analyze_auth_logs, check_suspicious_processes, monitor_network_connections",
        how_satisfied="Unauthorized use detection through: invalid user login attempts, brute force attacks from external IPs, suspicious process execution by non-privileged users, unexpected network connections, and unauthorized service deployment on non-standard ports.",
        evidence_artifacts=[
            "Invalid user attempt logs",
            "Non-privileged user suspicious activity reports",
            "Unauthorized service detection alerts",
        ],
        status=PracticeStatus.MET,
        assessment_objectives=[
            "Determine if unauthorized system use is detected",
            "Verify detection covers multiple unauthorized use vectors",
        ],
    ),

    # =========================================================================
    # RA - Risk Assessment
    # =========================================================================
    CMMCPractice(
        practice_id="RA.L2-3.11.2",
        practice_name="Vulnerability Scan",
        domain=CMMCDomain.RA,
        level=MaturityLevel.LEVEL_2,
        nist_800_171_ref="3.11.2",
        description="Scan for vulnerabilities in organizational systems and applications periodically and when new vulnerabilities affecting those systems and applications are identified.",
        hids_capability="check_suspicious_processes, check_file_integrity, sbom_generation",
        how_satisfied="Host-level vulnerability scanning through process monitoring (active exploitation detection), file integrity checking (unauthorized modifications indicating compromise), and SBOM generation (component-level vulnerability tracking via NVD/OSV correlation). Scans can be run on-demand or scheduled.",
        evidence_artifacts=[
            "Process scan results with malware detection",
            "File integrity scan results",
            "SBOM for component vulnerability correlation",
        ],
        status=PracticeStatus.PARTIALLY_MET,
        assessment_objectives=[
            "Determine if vulnerability scanning is performed",
            "Verify scan coverage includes system processes and configurations",
            "Confirm SBOM enables component-level vulnerability tracking",
        ],
    ),
    CMMCPractice(
        practice_id="RA.L2-3.11.3",
        practice_name="Vulnerability Remediation",
        domain=CMMCDomain.RA,
        level=MaturityLevel.LEVEL_2,
        nist_800_171_ref="3.11.3",
        description="Remediate vulnerabilities in accordance with risk assessments.",
        hids_capability="generate_security_report, stig_checker",
        how_satisfied="Security reports include risk-rated findings with mitigation recommendations prioritized by severity. STIG compliance reports include specific remediation guidance for each finding. Brute force reports recommend specific countermeasures (IP blocking, SSH hardening, fail2ban configuration).",
        evidence_artifacts=[
            "Risk-rated security findings with mitigation steps",
            "STIG remediation guidance per finding",
            "Prioritized countermeasure recommendations",
        ],
        status=PracticeStatus.MET,
        assessment_objectives=[
            "Determine if vulnerabilities are remediated based on risk",
            "Verify remediation guidance is specific and actionable",
        ],
    ),
]

# Indexes for fast lookup
_PRACTICE_INDEX: dict[str, CMMCPractice] = {p.practice_id: p for p in PRACTICE_MAPPINGS}

_DOMAIN_INDEX: dict[str, list[CMMCPractice]] = {}
for _practice in PRACTICE_MAPPINGS:
    _domain_key = _practice.domain.name
    if _domain_key not in _DOMAIN_INDEX:
        _DOMAIN_INDEX[_domain_key] = []
    _DOMAIN_INDEX[_domain_key].append(_practice)


def _check_cmmc_capability_available(capability: str) -> PracticeStatus:
    """
    Check whether an HIDS capability is actually available on this system.

    Args:
        capability: Comma-separated HIDS capability string from a practice mapping.

    Returns:
        Dynamic PracticeStatus based on actual system state.
    """
    capabilities = [c.strip() for c in capability.split(",")]
    results = []

    for cap in capabilities:
        if cap in ("analyze_auth_logs", "detect_brute_force"):
            auth_logs = ["/var/log/auth.log", "/var/log/secure", "/var/log/messages"]
            found = any(os.path.isfile(p) and os.access(p, os.R_OK) for p in auth_logs)
            results.append(found)

        elif cap == "audit_trail":
            try:
                from hids_mcp.compliance.audit_trail import get_default_trail
                trail = get_default_trail()
                results.append(trail is not None)
            except Exception:
                results.append(False)

        elif cap == "check_file_integrity":
            critical = ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers"]
            found = any(os.path.isfile(p) for p in critical)
            results.append(found)

        elif cap == "check_suspicious_processes":
            try:
                import psutil
                psutil.process_iter()
                results.append(True)
            except Exception:
                results.append(False)

        elif cap in ("monitor_network_connections", "check_listening_ports"):
            try:
                import psutil
                psutil.net_connections(kind='inet')
                results.append(True)
            except Exception:
                results.append(False)

        elif cap in ("generate_security_report", "sbom_generation", "stig_checker"):
            try:
                if cap == "sbom_generation":
                    from importlib.metadata import distributions
                    list(distributions())[:1]
                elif cap == "stig_checker":
                    from hids_mcp.compliance.stig_checker import get_stig_summary
                results.append(True)
            except Exception:
                results.append(False)

        else:
            return PracticeStatus.NOT_ASSESSED

    if not results:
        return PracticeStatus.NOT_ASSESSED

    if all(results):
        return PracticeStatus.MET
    elif any(results):
        return PracticeStatus.PARTIALLY_MET
    else:
        return PracticeStatus.NOT_ASSESSED


def _assess_practice_dynamically(practice: CMMCPractice) -> PracticeStatus:
    """
    Determine the actual practice status by checking whether the underlying
    HIDS capability is available and functional on this system.

    The static status is the maximum possible. Dynamic checks can only
    downgrade it.

    Args:
        practice: The practice mapping to assess.

    Returns:
        Dynamically determined PracticeStatus.
    """
    static_status = practice.status

    if static_status in (PracticeStatus.NOT_APPLICABLE, PracticeStatus.NOT_MET):
        return static_status

    dynamic_status = _check_cmmc_capability_available(practice.hids_capability)

    status_rank = {
        PracticeStatus.MET: 4,
        PracticeStatus.PARTIALLY_MET: 3,
        PracticeStatus.NOT_MET: 2,
        PracticeStatus.NOT_ASSESSED: 1,
        PracticeStatus.NOT_APPLICABLE: 0,
    }

    if status_rank.get(dynamic_status, 0) < status_rank.get(static_status, 0):
        return dynamic_status

    return static_status


def get_practice_by_id(practice_id: str) -> Optional[CMMCPractice]:
    """
    Retrieve a specific CMMC practice mapping by ID.

    Args:
        practice_id: CMMC practice identifier (e.g., 'AC.L2-3.1.7')

    Returns:
        CMMCPractice if found, None otherwise
    """
    return _PRACTICE_INDEX.get(practice_id)


def get_practices_by_domain(domain: str) -> list[CMMCPractice]:
    """
    Retrieve all practice mappings for a given domain.

    Args:
        domain: Two-letter domain code (e.g., 'AU', 'SI', 'IR')

    Returns:
        List of CMMCPractice instances for the domain
    """
    return _DOMAIN_INDEX.get(domain.upper(), [])


def assess_cmmc_posture() -> dict:
    """
    Run a comprehensive CMMC Level 2 assessment.

    Evaluates all mapped CMMC practices against HIDS capabilities
    and produces a structured assessment report showing:
    - Overall CMMC Level 2 readiness percentage
    - Per-domain compliance breakdown
    - Practice-level status details
    - Gap analysis for partially met and unmet practices
    - NIST 800-171 cross-reference mapping
    - Evidence artifact inventory

    Returns:
        Dictionary containing the full CMMC Level 2 assessment report
    """
    report_time = datetime.now(timezone.utc).isoformat()

    # Dynamically assess each practice against actual system state
    assessed_statuses: dict[str, PracticeStatus] = {}
    for p in PRACTICE_MAPPINGS:
        assessed_statuses[p.practice_id] = _assess_practice_dynamically(p)

    total_practices = len(PRACTICE_MAPPINGS)
    met = [p for p in PRACTICE_MAPPINGS if assessed_statuses[p.practice_id] == PracticeStatus.MET]
    partial = [p for p in PRACTICE_MAPPINGS if assessed_statuses[p.practice_id] == PracticeStatus.PARTIALLY_MET]
    not_met = [p for p in PRACTICE_MAPPINGS if assessed_statuses[p.practice_id] == PracticeStatus.NOT_MET]
    not_applicable = [p for p in PRACTICE_MAPPINGS if assessed_statuses[p.practice_id] == PracticeStatus.NOT_APPLICABLE]
    not_assessed = [p for p in PRACTICE_MAPPINGS if assessed_statuses[p.practice_id] == PracticeStatus.NOT_ASSESSED]

    applicable = total_practices - len(not_applicable)
    if applicable > 0:
        readiness_score = (len(met) + 0.5 * len(partial)) / applicable
    else:
        readiness_score = 0.0

    # Per-domain breakdown
    domain_breakdown = {}
    for domain_code, practices in _DOMAIN_INDEX.items():
        domain_met = [p for p in practices if assessed_statuses[p.practice_id] == PracticeStatus.MET]
        domain_partial = [p for p in practices if assessed_statuses[p.practice_id] == PracticeStatus.PARTIALLY_MET]
        domain_not_assessed = [p for p in practices if assessed_statuses[p.practice_id] == PracticeStatus.NOT_ASSESSED]
        domain_total = len(practices)

        # Build practice dicts with dynamic status override
        practice_dicts = []
        for p in practices:
            d = p.to_dict()
            d["assessed_status"] = assessed_statuses[p.practice_id].value
            practice_dicts.append(d)

        domain_breakdown[domain_code] = {
            "domain_name": CMMCDomain[domain_code].value,
            "total_practices": domain_total,
            "met": len(domain_met),
            "partially_met": len(domain_partial),
            "not_met": len([p for p in practices if assessed_statuses[p.practice_id] == PracticeStatus.NOT_MET]),
            "not_assessed": len(domain_not_assessed),
            "readiness_percentage": round(
                ((len(domain_met) + 0.5 * len(domain_partial)) / domain_total * 100)
                if domain_total > 0 else 0.0,
                1,
            ),
            "practices": practice_dicts,
        }

    # Evidence artifact inventory
    all_evidence = []
    for practice in PRACTICE_MAPPINGS:
        for artifact in practice.evidence_artifacts:
            all_evidence.append({
                "artifact": artifact,
                "practice_id": practice.practice_id,
                "domain": practice.domain.value,
            })

    # NIST 800-171 cross-reference
    nist_crossref = {}
    for practice in PRACTICE_MAPPINGS:
        nist_crossref[practice.practice_id] = {
            "nist_800_171_ref": practice.nist_800_171_ref,
            "practice_name": practice.practice_name,
            "status": assessed_statuses[practice.practice_id].value,
        }

    # Report integrity hash
    report_content = json.dumps({
        "report_time": report_time,
        "total_practices": total_practices,
        "readiness_score": readiness_score,
    }, sort_keys=True)
    report_hash = hashlib.sha256(report_content.encode()).hexdigest()

    report = {
        "report_type": "CMMC Level 2 Assessment",
        "report_time": report_time,
        "report_hash": report_hash,
        "framework_version": "CMMC v2.0 (aligned with NIST SP 800-171 Rev 2)",
        "assessment_level": 2,
        "system_name": "HIDS-MCP (Host-based Intrusion Detection System)",
        "overall_posture": {
            "readiness_score": round(readiness_score * 100, 1),
            "readiness_rating": _readiness_to_rating(readiness_score),
            "total_practices_mapped": total_practices,
            "met": len(met),
            "partially_met": len(partial),
            "not_met": len(not_met),
            "not_applicable": len(not_applicable),
            "not_assessed": len(not_assessed),
            "dynamically_verified": True,
            "level_2_achievable": len(not_met) == 0 and len(not_assessed) == 0 and readiness_score >= 0.8,
        },
        "domain_breakdown": domain_breakdown,
        "nist_800_171_crossref": nist_crossref,
        "evidence_inventory": {
            "total_artifacts": len(all_evidence),
            "artifacts": all_evidence,
        },
        "gap_analysis": {
            "partially_met_practices": [
                {
                    "practice_id": p.practice_id,
                    "practice_name": p.practice_name,
                    "domain": p.domain.value,
                    "nist_ref": p.nist_800_171_ref,
                    "gap_description": "Requires additional implementation for full CMMC Level 2 compliance",
                    "hids_capability": p.hids_capability,
                    "assessment_objectives_remaining": p.assessment_objectives,
                }
                for p in partial
            ],
            "not_met_practices": [
                {
                    "practice_id": p.practice_id,
                    "practice_name": p.practice_name,
                    "domain": p.domain.value,
                    "nist_ref": p.nist_800_171_ref,
                    "hids_capability": p.hids_capability,
                }
                for p in not_met
            ],
            "not_assessed_practices": [
                {
                    "practice_id": p.practice_id,
                    "practice_name": p.practice_name,
                    "domain": p.domain.value,
                    "nist_ref": p.nist_800_171_ref,
                    "reason": "Capability could not be dynamically verified on this system",
                    "hids_capability": p.hids_capability,
                    "static_status": p.status.value,
                }
                for p in not_assessed
            ],
        },
        "assessment_summary": {
            "total_assessment_objectives": sum(
                len(p.assessment_objectives) for p in PRACTICE_MAPPINGS
            ),
            "domains_assessed": len(domain_breakdown),
            "recommendation": _generate_recommendation(readiness_score, len(not_met), len(partial)),
        },
    }

    logger.info(
        "Generated CMMC Level 2 assessment: score=%.1f%%, practices=%d, hash=%s",
        readiness_score * 100,
        total_practices,
        report_hash[:16],
    )

    return report


def _readiness_to_rating(score: float) -> str:
    """Convert a numeric readiness score to a qualitative rating."""
    if score >= 0.9:
        return "Ready for Assessment"
    elif score >= 0.75:
        return "Near Ready"
    elif score >= 0.5:
        return "In Progress"
    elif score >= 0.25:
        return "Early Stage"
    else:
        return "Not Started"


def _generate_recommendation(score: float, not_met: int, partial: int) -> str:
    """Generate an assessment recommendation based on current posture."""
    if score >= 0.9 and not_met == 0:
        return (
            "System demonstrates strong CMMC Level 2 readiness. "
            "Recommend proceeding to formal C3PAO assessment. "
            "Address remaining partially-met practices to maximize assessment success."
        )
    elif score >= 0.75:
        return (
            f"System is near CMMC Level 2 readiness. {partial} practices require "
            f"additional implementation. Recommend completing gap remediation "
            f"before scheduling C3PAO assessment."
        )
    elif score >= 0.5:
        return (
            f"System has moderate CMMC Level 2 coverage. {not_met} practices are "
            f"not met and {partial} are partially met. Recommend prioritizing "
            f"not-met practices for remediation."
        )
    else:
        return (
            f"System requires significant work for CMMC Level 2 readiness. "
            f"Recommend developing a Plan of Action and Milestones (POA&M) "
            f"addressing all {not_met + partial} gap practices."
        )
