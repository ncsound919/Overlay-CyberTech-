"""
Security service for managing security events and state.

Provides business logic for:
- Creating and retrieving security events
- Managing security state
- Threat detection and response
"""

import hashlib
import time
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.models.schemas import (
    SecurityEventCreate,
    SecurityEventResponse,
    SecurityStateResponse,
    ThreatResponse,
)


class SecurityService:
    """
    Service for managing security operations.
    
    Integrates with the core platform components for threat detection
    and response management.
    """
    
    def __init__(self):
        """Initialize the security service."""
        self._events: Dict[str, Dict[str, Any]] = {}
        self._threats: Dict[str, Dict[str, Any]] = {}
        self._last_scan_timestamp: Optional[str] = None
        self._active_alerts: int = 0
        self._platform = None
        
    def _get_platform(self):
        """Lazy load the platform to avoid circular imports."""
        if self._platform is None:
            from main import OverlayCyberTech
            self._platform = OverlayCyberTech()
        return self._platform
    
    def _generate_event_id(self) -> str:
        """Generate a unique event ID."""
        return f"EVT-{uuid.uuid4().hex[:12].upper()}"
    
    def _generate_audit_hash(self, event_data: Dict[str, Any]) -> str:
        """Generate an audit hash for the event."""
        import json
        data_str = json.dumps(event_data, sort_keys=True, default=str)
        return hashlib.sha256(data_str.encode()).hexdigest()
    
    def create_event(self, event: SecurityEventCreate) -> SecurityEventResponse:
        """
        Create a new security event.
        
        Args:
            event: Security event data
            
        Returns:
            Created security event response
        """
        event_id = self._generate_event_id()
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        
        event_data = {
            "event_id": event_id,
            "event_type": event.event_type,
            "severity": event.severity,
            "detected_threat": event.detected_threat,
            "confidence_score": event.confidence_score,
            "affected_asset": event.affected_asset,
            "indicators_of_compromise": event.indicators_of_compromise,
            "metadata": event.metadata,
            "timestamp": timestamp,
        }
        
        audit_hash = self._generate_audit_hash(event_data)
        event_data["audit_hash"] = audit_hash
        
        # Determine if a playbook should be triggered
        playbook_triggered = None
        if event.severity == "CRITICAL":
            playbook_triggered = "incident_response_critical"
            self._active_alerts += 1
        elif event.severity == "HIGH" and event.confidence_score >= 0.9:
            playbook_triggered = "incident_response_high"
            self._active_alerts += 1
        
        event_data["playbook_triggered"] = playbook_triggered
        
        # Store event
        self._events[event_id] = event_data
        
        # Log to audit trail if platform is available
        try:
            platform = self._get_platform()
            platform.audit_log.append({
                "event_id": event_id,
                "event_type": event.event_type,
                "severity": event.severity,
                "data": event_data
            })
        except Exception:
            pass  # Continue even if audit logging fails
        
        return SecurityEventResponse(
            event_id=event_id,
            event_type=event.event_type,
            severity=event.severity,
            timestamp=timestamp,
            audit_hash=audit_hash,
            playbook_triggered=playbook_triggered
        )
    
    def get_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a security event by ID.
        
        Args:
            event_id: The event ID
            
        Returns:
            Event data or None if not found
        """
        return self._events.get(event_id)
    
    def list_events(
        self,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        List security events with optional filters.
        
        Args:
            event_type: Filter by event type
            severity: Filter by severity
            limit: Maximum number of events to return
            
        Returns:
            List of matching events
        """
        events = list(self._events.values())
        
        if event_type:
            events = [e for e in events if e.get("event_type") == event_type]
        
        if severity:
            events = [e for e in events if e.get("severity") == severity]
        
        # Sort by timestamp descending
        events.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
        
        return events[:limit]
    
    def get_security_state(self) -> SecurityStateResponse:
        """
        Get the current security state.
        
        Returns:
            Current security state
        """
        # Calculate device security score
        device_score = 100
        
        # Reduce score based on active alerts
        device_score -= min(self._active_alerts * 10, 50)
        
        # Check platform status
        try:
            platform = self._get_platform()
            status = platform.get_system_status()
            is_admin = status.get("platform", {}).get("is_admin", False)
            if not is_admin:
                device_score -= 10
        except Exception:
            device_score -= 5
        
        # Determine threat level based on active alerts
        if self._active_alerts >= 5:
            threat_level = "CRITICAL"
        elif self._active_alerts >= 3:
            threat_level = "HIGH"
        elif self._active_alerts >= 1:
            threat_level = "MEDIUM"
        else:
            threat_level = "NONE"
        
        return SecurityStateResponse(
            encryption_status=True,  # Assumed for now
            mfa_active=False,  # Would be set based on user config
            session_remaining_seconds=3600,  # Default 1 hour
            threat_level=threat_level,
            device_security_score=max(0, device_score),
            active_alerts=self._active_alerts,
            last_scan_timestamp=self._last_scan_timestamp
        )
    
    def get_threats(self, limit: int = 100) -> List[ThreatResponse]:
        """
        Get list of detected threats.
        
        Args:
            limit: Maximum number of threats to return
            
        Returns:
            List of threat responses
        """
        threats = list(self._threats.values())
        
        # Sort by first_detected descending
        threats.sort(key=lambda t: t.get("first_detected", ""), reverse=True)
        
        result = []
        for threat in threats[:limit]:
            result.append(ThreatResponse(
                threat_id=threat.get("threat_id", ""),
                threat_type=threat.get("threat_type", ""),
                severity=threat.get("severity", "MEDIUM"),
                confidence_score=threat.get("confidence_score", 0.0),
                first_detected=threat.get("first_detected", ""),
                last_activity=threat.get("last_activity", ""),
                status=threat.get("status", "active"),
                actions_taken=threat.get("actions_taken", [])
            ))
        
        return result
    
    def update_last_scan_timestamp(self) -> None:
        """Update the last scan timestamp to now."""
        self._last_scan_timestamp = datetime.utcnow().isoformat() + "Z"
    
    def reset_alerts(self) -> int:
        """
        Reset the alert counter.
        
        Returns:
            Number of alerts that were cleared
        """
        cleared = self._active_alerts
        self._active_alerts = 0
        return cleared
