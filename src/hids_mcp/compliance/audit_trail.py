"""
FedRAMP-Ready Audit Trail for HIDS-MCP.

Implements tamper-evident audit logging with cryptographic hash chaining
for federal information system compliance. Supports export to:
- CEF (Common Event Format) for ArcSight / generic SIEM
- LEEF (Log Event Extended Format) for IBM QRadar

Audit record format complies with:
- NIST SP 800-53 AU-3 (Content of Audit Records)
- NIST SP 800-53 AU-9 (Protection of Audit Information)
- NIST SP 800-53 AU-12 (Audit Record Generation)
- FedRAMP Moderate baseline requirements

Each audit event includes:
- UTC ISO 8601 timestamp
- Event type and severity
- Source IP and user identity
- Action and outcome
- NIST 800-53 control references
- CMMC practice references
- SHA-256 evidence hash with chain linking
"""

import hashlib
import json
import logging
import os
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class EventSeverity(Enum):
    """Audit event severity levels aligned with syslog severity."""
    CRITICAL = "critical"   # System is unusable / immediate action required
    HIGH = "high"           # Action must be taken immediately
    MEDIUM = "medium"       # Warning conditions / notable events
    LOW = "low"             # Normal but significant conditions
    INFO = "informational"  # Informational messages


class EventOutcome(Enum):
    """Audit event outcome classification."""
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class EventType(Enum):
    """Audit event type categories."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    FILE_INTEGRITY = "file_integrity"
    PROCESS_MONITORING = "process_monitoring"
    NETWORK_MONITORING = "network_monitoring"
    CONFIGURATION_CHANGE = "configuration_change"
    COMPLIANCE_CHECK = "compliance_check"
    SYSTEM_EVENT = "system_event"
    INCIDENT = "incident"
    AUDIT_SYSTEM = "audit_system"


@dataclass
class AuditEvent:
    """
    FedRAMP-compliant audit event record.

    Satisfies NIST SP 800-53 AU-3 content requirements:
    - What type of event occurred
    - When the event occurred
    - Where the event occurred
    - Source of the event
    - Outcome of the event
    - Identity of individuals/subjects/objects
    """
    event_type: EventType
    severity: EventSeverity
    action: str
    outcome: EventOutcome
    source_ip: str = ""
    user_id: str = ""
    target: str = ""
    description: str = ""
    nist_controls: list[str] = field(default_factory=list)
    cmmc_practices: list[str] = field(default_factory=list)
    additional_data: dict = field(default_factory=dict)
    # Auto-populated fields
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    hostname: str = field(default_factory=lambda: os.uname().nodename)
    evidence_hash: str = ""
    previous_hash: str = ""
    sequence_number: int = 0

    def compute_evidence_hash(self) -> str:
        """
        Compute SHA-256 evidence hash for this event.

        The hash covers all content fields but excludes the evidence_hash
        field itself to avoid circular dependency.
        """
        content = json.dumps({
            "timestamp": self.timestamp,
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "action": self.action,
            "outcome": self.outcome.value,
            "source_ip": self.source_ip,
            "user_id": self.user_id,
            "target": self.target,
            "description": self.description,
            "hostname": self.hostname,
            "nist_controls": self.nist_controls,
            "cmmc_practices": self.cmmc_practices,
            "additional_data": self.additional_data,
            "previous_hash": self.previous_hash,
            "sequence_number": self.sequence_number,
        }, sort_keys=True)
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        result = asdict(self)
        result["event_type"] = self.event_type.value
        result["severity"] = self.severity.value
        result["outcome"] = self.outcome.value
        return result

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True)


class AuditTrail:
    """
    Tamper-evident audit trail with SHA-256 hash chaining.

    Each log entry includes the hash of the previous entry, forming a
    cryptographic chain that enables detection of any modification,
    insertion, or deletion of audit records.

    Thread-safe for concurrent audit event recording.
    """

    def __init__(
        self,
        storage_path: Optional[str] = None,
        retention_days: int = 365,
        max_events_in_memory: int = 10000,
    ):
        """
        Initialize the audit trail.

        Args:
            storage_path: Path for persistent audit storage (JSON lines format).
                         If None, events are held in memory only.
            retention_days: Number of days to retain audit records.
            max_events_in_memory: Maximum events to hold in memory buffer.
        """
        self._events: list[AuditEvent] = []
        self._lock = threading.Lock()
        self._sequence_counter = 0
        self._last_hash = hashlib.sha256(b"GENESIS").hexdigest()
        self._storage_path = storage_path
        self._retention_days = retention_days
        self._max_events_in_memory = max_events_in_memory

        if storage_path:
            self._ensure_storage_directory(storage_path)
            self._load_last_hash(storage_path)

        logger.info(
            "Audit trail initialized: storage=%s, retention=%d days",
            storage_path or "memory-only",
            retention_days,
        )

    def _ensure_storage_directory(self, path: str) -> None:
        """Create storage directory if it doesn't exist."""
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)

    def _load_last_hash(self, path: str) -> None:
        """Load the last hash from existing audit log for chain continuity."""
        if not os.path.exists(path):
            return

        try:
            last_line = ""
            with open(path, "r") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        last_line = stripped
            if last_line:
                event_data = json.loads(last_line)
                self._last_hash = event_data.get("evidence_hash", self._last_hash)
                self._sequence_counter = event_data.get("sequence_number", 0)
                logger.info(
                    "Resumed audit chain from sequence %d, hash %s",
                    self._sequence_counter,
                    self._last_hash[:16],
                )
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Could not load previous audit chain state: %s", str(e))

    def record(self, event: AuditEvent) -> AuditEvent:
        """
        Record an audit event with hash chain linking.

        Args:
            event: The AuditEvent to record.

        Returns:
            The event with populated hash chain fields.
        """
        with self._lock:
            self._sequence_counter += 1
            event.sequence_number = self._sequence_counter
            event.previous_hash = self._last_hash
            event.evidence_hash = event.compute_evidence_hash()
            self._last_hash = event.evidence_hash

            # Store in memory buffer
            self._events.append(event)
            if len(self._events) > self._max_events_in_memory:
                self._events = self._events[-self._max_events_in_memory:]

            # Persist to file
            if self._storage_path:
                self._persist_event(event)

            logger.debug(
                "Audit event recorded: seq=%d, type=%s, hash=%s",
                event.sequence_number,
                event.event_type.value,
                event.evidence_hash[:16],
            )

        return event

    def _persist_event(self, event: AuditEvent) -> None:
        """Append event to persistent storage as JSON lines."""
        try:
            with open(self._storage_path, "a") as f:
                f.write(event.to_json() + "\n")
        except OSError as e:
            logger.error("Failed to persist audit event: %s", str(e))

    def verify_integrity(self) -> dict:
        """
        Verify the integrity of the entire audit hash chain.

        Checks that each event's evidence_hash is correct and that
        the previous_hash field correctly references its predecessor.

        Returns:
            Dictionary with verification results including any
            integrity violations found.
        """
        events_to_verify = self._events

        if self._storage_path and os.path.exists(self._storage_path):
            events_to_verify = self._load_all_events()

        if not events_to_verify:
            return {
                "verified": True,
                "total_events": 0,
                "violations": [],
                "chain_intact": True,
            }

        violations = []
        genesis_hash = hashlib.sha256(b"GENESIS").hexdigest()
        expected_previous = genesis_hash

        for i, event in enumerate(events_to_verify):
            # Verify evidence hash
            computed_hash = event.compute_evidence_hash()
            if computed_hash != event.evidence_hash:
                violations.append({
                    "sequence": event.sequence_number,
                    "violation": "evidence_hash_mismatch",
                    "expected": computed_hash,
                    "actual": event.evidence_hash,
                })

            # Verify chain link (skip first event if we don't know the genesis)
            if i == 0 and event.previous_hash != genesis_hash:
                # May have resumed from a previous chain - acceptable
                pass
            elif i > 0 and event.previous_hash != events_to_verify[i - 1].evidence_hash:
                violations.append({
                    "sequence": event.sequence_number,
                    "violation": "chain_link_broken",
                    "expected_previous": events_to_verify[i - 1].evidence_hash,
                    "actual_previous": event.previous_hash,
                })

        return {
            "verified": len(violations) == 0,
            "total_events": len(events_to_verify),
            "violations": violations,
            "chain_intact": len(violations) == 0,
            "first_sequence": events_to_verify[0].sequence_number if events_to_verify else None,
            "last_sequence": events_to_verify[-1].sequence_number if events_to_verify else None,
            "verification_time": datetime.now(timezone.utc).isoformat(),
        }

    def _load_all_events(self) -> list[AuditEvent]:
        """Load all events from persistent storage."""
        events = []
        try:
            with open(self._storage_path, "r") as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        data = json.loads(stripped)
                        event = AuditEvent(
                            event_type=EventType(data["event_type"]),
                            severity=EventSeverity(data["severity"]),
                            action=data["action"],
                            outcome=EventOutcome(data["outcome"]),
                            source_ip=data.get("source_ip", ""),
                            user_id=data.get("user_id", ""),
                            target=data.get("target", ""),
                            description=data.get("description", ""),
                            nist_controls=data.get("nist_controls", []),
                            cmmc_practices=data.get("cmmc_practices", []),
                            additional_data=data.get("additional_data", {}),
                            timestamp=data.get("timestamp", ""),
                            hostname=data.get("hostname", ""),
                            evidence_hash=data.get("evidence_hash", ""),
                            previous_hash=data.get("previous_hash", ""),
                            sequence_number=data.get("sequence_number", 0),
                        )
                        events.append(event)
                    except (KeyError, ValueError) as e:
                        logger.warning("Skipping malformed audit event: %s", str(e))
        except OSError as e:
            logger.error("Failed to load audit events: %s", str(e))
        return events

    def get_events(
        self,
        event_type: Optional[EventType] = None,
        severity: Optional[EventSeverity] = None,
        since: Optional[str] = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """
        Query audit events with optional filters.

        Args:
            event_type: Filter by event type.
            severity: Filter by minimum severity.
            since: ISO 8601 timestamp - return events after this time.
            limit: Maximum events to return.

        Returns:
            List of matching AuditEvent instances.
        """
        with self._lock:
            filtered = list(self._events)

        if event_type:
            filtered = [e for e in filtered if e.event_type == event_type]

        if severity:
            severity_order = [
                EventSeverity.INFO,
                EventSeverity.LOW,
                EventSeverity.MEDIUM,
                EventSeverity.HIGH,
                EventSeverity.CRITICAL,
            ]
            min_index = severity_order.index(severity)
            filtered = [
                e for e in filtered
                if severity_order.index(e.severity) >= min_index
            ]

        if since:
            filtered = [e for e in filtered if e.timestamp >= since]

        return filtered[-limit:]

    def enforce_retention(self) -> dict:
        """
        Enforce the retention policy by removing events older than retention_days.

        Returns:
            Dictionary with retention enforcement results.
        """
        cutoff = datetime.now(timezone.utc)
        from datetime import timedelta
        cutoff = cutoff - timedelta(days=self._retention_days)
        cutoff_str = cutoff.isoformat()

        with self._lock:
            before_count = len(self._events)
            self._events = [e for e in self._events if e.timestamp >= cutoff_str]
            removed = before_count - len(self._events)

        logger.info(
            "Retention enforcement: removed %d events older than %d days",
            removed,
            self._retention_days,
        )

        return {
            "retention_days": self._retention_days,
            "cutoff": cutoff_str,
            "events_before": before_count,
            "events_after": before_count - removed,
            "events_removed": removed,
        }

    @property
    def event_count(self) -> int:
        """Return the current number of events in memory."""
        return len(self._events)

    @property
    def last_hash(self) -> str:
        """Return the hash of the most recent event."""
        return self._last_hash


def export_to_cef(events: list[AuditEvent]) -> str:
    """
    Export audit events to CEF (Common Event Format).

    CEF is the standard format for ArcSight and many other SIEM platforms.

    Format: CEF:Version|Device Vendor|Device Product|Device Version|
            Signature ID|Name|Severity|Extension

    Args:
        events: List of AuditEvent instances to export.

    Returns:
        CEF formatted string with one event per line.
    """
    cef_severity_map = {
        EventSeverity.CRITICAL: 10,
        EventSeverity.HIGH: 8,
        EventSeverity.MEDIUM: 5,
        EventSeverity.LOW: 3,
        EventSeverity.INFO: 1,
    }

    lines = []
    for event in events:
        severity_num = cef_severity_map.get(event.severity, 5)

        # Escape CEF special characters in values
        def cef_escape(value: str) -> str:
            return value.replace("\\", "\\\\").replace("|", "\\|").replace("\n", "\\n")

        # Build extension key-value pairs
        extensions = []
        extensions.append(f"rt={event.timestamp}")
        if event.source_ip:
            extensions.append(f"src={event.source_ip}")
        if event.user_id:
            extensions.append(f"suser={cef_escape(event.user_id)}")
        if event.target:
            extensions.append(f"dhost={cef_escape(event.target)}")
        extensions.append(f"act={cef_escape(event.action)}")
        extensions.append(f"outcome={event.outcome.value}")
        extensions.append(f"cs1={cef_escape(','.join(event.nist_controls))}")
        extensions.append("cs1Label=NISTControls")
        extensions.append(f"cs2={cef_escape(','.join(event.cmmc_practices))}")
        extensions.append("cs2Label=CMMCPractices")
        extensions.append(f"cs3={event.evidence_hash}")
        extensions.append("cs3Label=EvidenceHash")
        extensions.append(f"cn1={event.sequence_number}")
        extensions.append("cn1Label=SequenceNumber")

        cef_line = (
            f"CEF:0|2AcreStudios|HIDS-MCP|1.0.0"
            f"|{cef_escape(event.event_type.value)}"
            f"|{cef_escape(event.action)}"
            f"|{severity_num}"
            f"|{' '.join(extensions)}"
        )
        lines.append(cef_line)

    return "\n".join(lines)


def export_to_leef(events: list[AuditEvent]) -> str:
    """
    Export audit events to LEEF (Log Event Extended Format).

    LEEF is the standard format for IBM QRadar SIEM.

    Format: LEEF:Version|Vendor|Product|Version|EventID|
            key=value<tab>key=value...

    Args:
        events: List of AuditEvent instances to export.

    Returns:
        LEEF formatted string with one event per line.
    """
    leef_severity_map = {
        EventSeverity.CRITICAL: 10,
        EventSeverity.HIGH: 8,
        EventSeverity.MEDIUM: 5,
        EventSeverity.LOW: 3,
        EventSeverity.INFO: 1,
    }

    lines = []
    for event in events:
        severity_num = leef_severity_map.get(event.severity, 5)

        # LEEF uses tab-separated key=value pairs
        kvpairs = []
        kvpairs.append(f"devTime={event.timestamp}")
        kvpairs.append(f"sev={severity_num}")
        if event.source_ip:
            kvpairs.append(f"src={event.source_ip}")
        if event.user_id:
            kvpairs.append(f"usrName={event.user_id}")
        if event.target:
            kvpairs.append(f"dst={event.target}")
        kvpairs.append(f"action={event.action}")
        kvpairs.append(f"outcome={event.outcome.value}")
        kvpairs.append(f"nistControls={','.join(event.nist_controls)}")
        kvpairs.append(f"cmmcPractices={','.join(event.cmmc_practices)}")
        kvpairs.append(f"evidenceHash={event.evidence_hash}")
        kvpairs.append(f"sequenceNumber={event.sequence_number}")
        kvpairs.append(f"description={event.description}")

        leef_line = (
            f"LEEF:2.0|2AcreStudios|HIDS-MCP|1.0.0|{event.event_type.value}|"
            + "\t".join(kvpairs)
        )
        lines.append(leef_line)

    return "\n".join(lines)


# Module-level audit trail instance for shared use
_default_trail: Optional[AuditTrail] = None
_trail_lock = threading.Lock()


def get_default_trail(storage_path: Optional[str] = None) -> AuditTrail:
    """
    Get or create the default audit trail instance.

    Args:
        storage_path: Optional path for persistent storage.

    Returns:
        The shared AuditTrail instance.
    """
    global _default_trail
    with _trail_lock:
        if _default_trail is None:
            _default_trail = AuditTrail(storage_path=storage_path)
        return _default_trail
