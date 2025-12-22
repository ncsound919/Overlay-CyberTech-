"""
Request and response schemas for the API.

These schemas define the structure of data exchanged through the API.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """Security event severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ThreatLevel(str, Enum):
    """Threat level classification."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


class EventType(str, Enum):
    """Types of security events."""
    PROMPT_INJECTION = "prompt_injection"
    ZERO_DAY = "zero_day"
    ROGUE_AGENT = "rogue_agent"
    INTRUSION = "intrusion"
    MALWARE = "malware"
    DDOS = "ddos"
    DATA_BREACH = "data_breach"
    UNAUTHORIZED_ACCESS = "unauthorized_access"


# Request Schemas

@dataclass
class SecurityEventCreate:
    """Schema for creating a security event."""
    event_type: str
    severity: str
    detected_threat: str
    confidence_score: float
    affected_asset: str
    indicators_of_compromise: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self) -> None:
        """Validate fields after initialization."""
        # Validate required string fields are non-empty
        for field_name in ("event_type", "severity", "detected_threat", "affected_asset"):
            value = getattr(self, field_name)
            if not isinstance(value, str):
                raise ValueError(f"{field_name} must be a string, got {type(value).__name__}")
            stripped = value.strip()
            if not stripped:
                raise ValueError(f"{field_name} must be a non-empty string")
            setattr(self, field_name, stripped)
        
        # Validate confidence_score is between 0.0 and 1.0
        if not isinstance(self.confidence_score, (int, float)):
            raise ValueError("confidence_score must be a number")
        if self.confidence_score < 0.0 or self.confidence_score > 1.0:
            raise ValueError("confidence_score must be between 0.0 and 1.0")


@dataclass
class ScanRequest:
    """Schema for initiating a security scan."""
    target_path: Optional[str] = None
    scan_type: str = "full"
    detailed: bool = False
    auto_respond: bool = False


@dataclass
class PlaybookExecuteRequest:
    """Schema for executing a SOAR playbook."""
    playbook_id: str
    alert_id: str
    context: Dict[str, Any] = field(default_factory=dict)


# Response Schemas

@dataclass
class SecurityEventResponse:
    """Response schema for security events."""
    event_id: str
    event_type: str
    severity: str
    timestamp: str
    audit_hash: str
    playbook_triggered: Optional[str] = None


@dataclass
class SecurityStateResponse:
    """Response schema for security state."""
    encryption_status: bool
    mfa_active: bool
    session_remaining_seconds: int
    threat_level: str
    device_security_score: int
    active_alerts: int
    last_scan_timestamp: Optional[str] = None


@dataclass
class ThreatResponse:
    """Response schema for threat information."""
    threat_id: str
    threat_type: str
    severity: str
    confidence_score: float
    first_detected: str
    last_activity: str
    status: str
    actions_taken: List[str] = field(default_factory=list)


@dataclass
class ScanResponse:
    """Response schema for scan results."""
    scan_id: str
    status: str
    timestamp: str
    threats_detected: int
    intruders_found: int
    risk_level: str
    recommendations: List[str] = field(default_factory=list)
    details: Optional[Dict[str, Any]] = None


@dataclass
class PlaybookExecuteResponse:
    """Response schema for playbook execution."""
    playbook_execution_id: str
    playbook_id: str
    status: str
    actions_executed: List[Dict[str, str]] = field(default_factory=list)
    completion_time_seconds: float = 0.0


@dataclass
class SystemStatusResponse:
    """Response schema for system status."""
    platform: Dict[str, Any] = field(default_factory=dict)
    security: Dict[str, Any] = field(default_factory=dict)
    uptime_seconds: float = 0.0
    version: str = "1.0.0"


@dataclass
class HealthCheckResponse:
    """Response schema for health check."""
    status: str
    timestamp: str
    components: Dict[str, str] = field(default_factory=dict)
