"""
Defense-grade compliance framework for HIDS-MCP.

Provides mappings and assessments for:
- NIST SP 800-53 Rev 5 control families
- CMMC Level 2 practice alignment
- DISA STIG compliance checking
- FedRAMP-ready audit trail with tamper-evident logging
- CycloneDX SBOM generation for supply chain security
"""

from hids_mcp.compliance.nist_800_53 import (
    get_compliance_report,
    map_alert_to_controls,
    get_control_by_id,
    get_controls_by_family,
)
from hids_mcp.compliance.cmmc import (
    assess_cmmc_posture,
    get_practice_by_id,
    get_practices_by_domain,
)
from hids_mcp.compliance.stig_checker import (
    run_stig_checks,
    run_single_stig_check,
    get_stig_summary,
)
from hids_mcp.compliance.audit_trail import (
    AuditTrail,
    AuditEvent,
    export_to_cef,
    export_to_leef,
)
from hids_mcp.compliance.sbom import (
    generate_sbom,
    generate_sbom_json,
)

__all__ = [
    "get_compliance_report",
    "map_alert_to_controls",
    "get_control_by_id",
    "get_controls_by_family",
    "assess_cmmc_posture",
    "get_practice_by_id",
    "get_practices_by_domain",
    "run_stig_checks",
    "run_single_stig_check",
    "get_stig_summary",
    "AuditTrail",
    "AuditEvent",
    "export_to_cef",
    "export_to_leef",
    "generate_sbom",
    "generate_sbom_json",
]
