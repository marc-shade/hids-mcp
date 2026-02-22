# Host-based IDS MCP Server

[![MCP](https://img.shields.io/badge/MCP-Compatible-blue)](https://modelcontextprotocol.io)
[![Python-3.10+](https://img.shields.io/badge/Python-3.10%2B-green)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Part of Agentic System](https://img.shields.io/badge/Part_of-Agentic_System-brightgreen)](https://github.com/marc-shade/agentic-system-oss)
[![NIST 800-53](https://img.shields.io/badge/NIST_800--53-Rev_5-blue)](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
[![CMMC](https://img.shields.io/badge/CMMC-Level_2-green)](https://www.acq.osd.mil/cmmc/)
[![STIG](https://img.shields.io/badge/DISA-STIG-orange)](https://public.cyber.mil/stigs/)
[![CycloneDX](https://img.shields.io/badge/SBOM-CycloneDX_1.5-purple)](https://cyclonedx.org/)

> **Defense-grade host-based intrusion detection with federal compliance framework.**

Part of the [Agentic System](https://github.com/marc-shade/agentic-system-oss) - a 24/7 autonomous AI framework with persistent memory.

Host-based Intrusion Detection System for monitoring local system security with built-in compliance mapping for NIST SP 800-53, CMMC Level 2, DISA STIG, and FedRAMP-ready audit trail.

## Features

### Core HIDS Capabilities
- **Auth Log Analysis**: Failed logins, brute force detection, privilege escalation
- **Process Monitoring**: Suspicious processes, unusual activity patterns
- **File Integrity**: Detect unauthorized changes to critical files via SHA-256 hashing
- **Network Connections**: Monitor active connections, detect C2 backdoors
- **Listening Port Audit**: Identify unauthorized listening services

### Compliance & Defense Standards
- **NIST SP 800-53 Rev 5**: 18 controls mapped across 8 families (AU, SI, IR, CM, AC, SC, SA, RA) with evidence generation and assessment procedures
- **CMMC Level 2**: 22 practices mapped across 7 domains aligned with NIST SP 800-171 Rev 2 for CUI protection
- **DISA STIG**: 11 automated compliance checks (V-230264 through V-230478) covering file integrity, audit log protection, login monitoring, privilege escalation, SSH hardening, and password complexity
- **FedRAMP-Ready Audit Trail**: Tamper-evident logging with SHA-256 hash chaining, CEF/LEEF SIEM export, and retention policy enforcement
- **Supply Chain Security (SBOM)**: CycloneDX 1.5 Software Bill of Materials generation per Executive Order 14028

## Tools

### HIDS Monitoring Tools

| Tool | Description |
|------|-------------|
| `analyze_auth_logs` | Parse auth/secure logs for security events |
| `detect_brute_force` | Find brute force login attempts with configurable thresholds |
| `check_suspicious_processes` | Identify suspicious running processes (malware, miners, reverse shells) |
| `monitor_network_connections` | Check active network connections for C2 indicators |
| `check_listening_ports` | Find all listening services and unauthorized ports |
| `check_file_integrity` | Verify critical file checksums against baselines |
| `generate_security_report` | Comprehensive multi-vector host security report |

### Compliance Tools

| Tool | Description | Framework |
|------|-------------|-----------|
| `hids_compliance_report` | Generate NIST 800-53 compliance posture report | NIST SP 800-53 Rev 5 |
| `hids_cmmc_assessment` | Run CMMC Level 2 practice assessment | CMMC v2.0 / NIST 800-171 |
| `hids_stig_check` | Run DISA STIG compliance checks (all or by ID) | DISA STIG |
| `hids_audit_export` | Export tamper-evident audit trail in CEF/LEEF format | FedRAMP |
| `hids_generate_sbom` | Generate CycloneDX 1.5 Software Bill of Materials | EO 14028 / NIST CM-8 |

## Compliance & Defense Standards

### NIST SP 800-53 Rev 5 Control Mapping

The HIDS maps to 18 controls across 8 control families:

| Family | Controls | Coverage |
|--------|----------|----------|
| **AU** - Audit and Accountability | AU-2, AU-3, AU-5, AU-6, AU-8, AU-9, AU-12 | Event logging, content, review, protection, generation |
| **SI** - System and Information Integrity | SI-3, SI-4, SI-5, SI-7 | Malicious code protection, monitoring, integrity verification |
| **IR** - Incident Response | IR-4, IR-5, IR-6 | Handling, monitoring, reporting |
| **CM** - Configuration Management | CM-3, CM-6, CM-8 | Change control, settings, inventory |
| **AC** - Access Control | AC-7, AC-17 | Unsuccessful logon, remote access |
| **SC** - System/Communications Protection | SC-7 | Boundary protection |
| **SA** - System and Services Acquisition | SA-11 | Developer testing and evaluation |
| **RA** - Risk Assessment | RA-5 | Vulnerability monitoring |

Each mapping includes: control ID, description, HIDS capability, how the control is satisfied, evidence generation method, and assessment procedures.

### CMMC Level 2 Practice Alignment

22 practices mapped across 7 domains aligned with NIST SP 800-171 Rev 2:

| Domain | Practices | Key Areas |
|--------|-----------|-----------|
| **AC** - Access Control | 3 | Unsuccessful logon limits, session monitoring, remote access |
| **AU** - Audit & Accountability | 6 | System auditing, record content, failure alerting, review, protection |
| **CM** - Configuration Management | 3 | Baselining, change management, access restrictions |
| **IR** - Incident Response | 2 | Handling, reporting |
| **RA** - Risk Assessment | 2 | Vulnerability scanning, remediation |
| **SC** - System & Comms Protection | 2 | Boundary protection, default-deny |
| **SI** - System & Info Integrity | 4 | Flaw remediation, malware protection, alerts, monitoring |

Assessment produces: readiness score, per-domain breakdown, NIST 800-171 cross-references, evidence artifact inventory, and gap analysis with remediation guidance.

### DISA STIG Compliance Checking

Automated checks for RHEL 8 STIG requirements:

| STIG ID | Severity | Check |
|---------|----------|-------|
| V-230264 | CAT I | File integrity tool installed (AIDE/Tripwire/OSSEC) |
| V-230265 | CAT II | File integrity baseline exists and is current |
| V-230266 | CAT II | System file modification alerts configured |
| V-230310 | CAT II | Login attempts are monitored |
| V-230311 | CAT II | Privilege escalation events audited |
| V-230312 | CAT II | Password complexity enforced |
| V-230313 | CAT I | SSH root login disabled |
| V-230383 | CAT I | Critical system file permissions correct |
| V-230398 | CAT II | Audit log permissions (mode 0600) |
| V-230399 | CAT II | Audit log directory permissions (mode 0750) |
| V-230478 | CAT II | Audit service (auditd) running |

Each finding includes: STIG ID, severity (CAT I/II/III), status (PASS/FAIL/NOT_APPLICABLE), finding details, CCI references, NIST control mappings, and specific remediation guidance.

### FedRAMP-Ready Audit Trail

Tamper-evident audit logging with cryptographic integrity:

- **Format**: UTC ISO 8601 timestamps, event type, severity, source IP, user ID, action, outcome
- **Compliance Tags**: NIST 800-53 controls and CMMC practices on every event
- **Integrity**: SHA-256 hash chain (each entry includes hash of predecessor)
- **Export**: CEF (ArcSight/generic SIEM) and LEEF (IBM QRadar) formats
- **Retention**: Configurable retention policy enforcement
- **Verification**: Built-in chain integrity verification detects tampering

### Supply Chain Security (SBOM)

CycloneDX 1.5 Software Bill of Materials per Executive Order 14028:

- Complete component inventory with versions and descriptions
- SPDX license identification
- SHA-256 component hashes for integrity verification
- Package URLs (purl) for universal identification
- Dependency graph mapping
- Supplier information
- NTIA minimum element compliance

### Zero Trust Architecture Integration

The HIDS supports Zero Trust principles through:

1. **Never Trust, Always Verify**: Every process, connection, and file is evaluated regardless of location
2. **Continuous Monitoring**: Real-time assessment across authentication, processes, network, and file integrity
3. **Least Privilege Detection**: Monitors for privilege escalation and unauthorized access patterns
4. **Micro-segmentation Support**: Network connection analysis identifies lateral movement
5. **Assume Breach**: Active detection of C2 communications, malware signatures, and post-exploitation tools
6. **Evidence-Based Access**: Tamper-evident audit trail provides cryptographic proof of all security events

## Monitored Log Files

- `/var/log/auth.log` (Debian/Ubuntu)
- `/var/log/secure` (RHEL/Fedora)
- `/var/log/messages`
- `/var/log/syslog`

## Suspicious Process Indicators

- Hidden processes (names starting with .)
- Processes from /tmp or /dev/shm
- Processes with deleted executables
- Known malware process names (xmrig, mimikatz, hydra, etc.)
- Reverse shell indicators (nc, ncat, socat)
- Unusual parent-child relationships

## Installation

```bash
pip install -e .
```

## Usage

```bash
# Run the MCP server
hids-mcp

# Or directly
python -m hids_mcp.server
```

### Example: Generate Compliance Report

```python
# Via MCP tool call
result = await hids_compliance_report()
# Returns NIST 800-53 compliance posture with score, family breakdown, gap analysis

result = await hids_cmmc_assessment()
# Returns CMMC Level 2 readiness with domain breakdown, evidence inventory

result = await hids_stig_check()
# Returns all STIG check results with pass/fail, severity, remediation

result = await hids_stig_check(stig_id="V-230313")
# Returns single STIG check: SSH root login disabled

result = await hids_audit_export(format="cef")
# Returns CEF formatted events for SIEM ingestion

result = await hids_generate_sbom()
# Returns CycloneDX 1.5 SBOM with component inventory
```

---

## Part of the MCP Ecosystem

This server integrates with other MCP servers for comprehensive AGI capabilities:

| Server | Purpose |
|--------|---------|
| [enhanced-memory-mcp](https://github.com/marc-shade/enhanced-memory-mcp) | 4-tier persistent memory with semantic search |
| [agent-runtime-mcp](https://github.com/marc-shade/agent-runtime-mcp) | Persistent task queues and goal decomposition |
| [agi-mcp](https://github.com/marc-shade/agi-mcp) | Full AGI orchestration with 21 tools |
| [cluster-execution-mcp](https://github.com/marc-shade/cluster-execution-mcp) | Distributed task routing across nodes |
| [node-chat-mcp](https://github.com/marc-shade/node-chat-mcp) | Inter-node AI communication |
| [ember-mcp](https://github.com/marc-shade/ember-mcp) | Production-only policy enforcement |

See [agentic-system-oss](https://github.com/marc-shade/agentic-system-oss) for the complete framework.
