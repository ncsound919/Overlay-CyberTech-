"""
Security routes for the backend API.

Provides endpoints for:
- POST /api/security/events - Create security event
- GET /api/security/events - List security events
- GET /api/security/events/{id} - Get security event
- GET /api/security/state - Get security state
- GET /api/security/threats - Get detected threats
"""

from typing import Any, Dict, List, Optional

from backend.middleware.auth import User, authenticate_request
from backend.middleware.rate_limiter import check_rate_limit, RateLimitError
from backend.models.schemas import SecurityEventCreate
from backend.services.security_service import SecurityService


class SecurityRoutes:
    """
    Route handlers for security endpoints.
    
    Usage:
        routes = SecurityRoutes()
        
        # Create event
        response = routes.create_event(event_data, auth_header, ip_address)
        
        # Get state
        state = routes.get_state(auth_header, ip_address)
    """
    
    def __init__(self, service: Optional[SecurityService] = None):
        """
        Initialize security routes.
        
        Args:
            service: Optional SecurityService instance
        """
        self.service = service or SecurityService()
    
    def _check_auth_and_rate_limit(
        self,
        auth_header: Optional[str],
        ip_address: str
    ) -> User:
        """
        Check authentication and rate limits.
        
        Args:
            auth_header: Authorization header
            ip_address: Client IP address
            
        Returns:
            Authenticated user
            
        Raises:
            AuthenticationError: If authentication fails
            RateLimitError: If rate limit exceeded
        """
        # Authenticate
        user = authenticate_request(auth_header)
        
        # Check rate limit
        allowed, retry_after = check_rate_limit(ip_address, user.user_id)
        if not allowed:
            raise RateLimitError(
                "Rate limit exceeded",
                retry_after=retry_after
            )
        
        return user
    
    def create_event(
        self,
        event_data: Dict[str, Any],
        auth_header: Optional[str] = None,
        ip_address: str = "127.0.0.1"
    ) -> Dict[str, Any]:
        """
        Create a new security event.
        
        POST /api/security/events
        
        Args:
            event_data: Event data
            auth_header: Authorization header
            ip_address: Client IP address
            
        Returns:
            Created event response
        """
        self._check_auth_and_rate_limit(auth_header, ip_address)
        
        # Create event from data
        event = SecurityEventCreate(
            event_type=event_data.get("event_type", ""),
            severity=event_data.get("severity", "MEDIUM"),
            detected_threat=event_data.get("detected_threat", ""),
            confidence_score=float(event_data.get("confidence_score", 0.0)),
            affected_asset=event_data.get("affected_asset", ""),
            indicators_of_compromise=event_data.get("indicators_of_compromise", []),
            metadata=event_data.get("metadata", {})
        )
        
        response = self.service.create_event(event)
        
        return {
            "event_id": response.event_id,
            "event_type": response.event_type,
            "severity": response.severity,
            "timestamp": response.timestamp,
            "audit_hash": response.audit_hash,
            "playbook_triggered": response.playbook_triggered
        }
    
    def get_event(
        self,
        event_id: str,
        auth_header: Optional[str] = None,
        ip_address: str = "127.0.0.1"
    ) -> Optional[Dict[str, Any]]:
        """
        Get a security event by ID.
        
        GET /api/security/events/{event_id}
        
        Args:
            event_id: Event ID
            auth_header: Authorization header
            ip_address: Client IP address
            
        Returns:
            Event data or None
        """
        self._check_auth_and_rate_limit(auth_header, ip_address)
        return self.service.get_event(event_id)
    
    def list_events(
        self,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
        auth_header: Optional[str] = None,
        ip_address: str = "127.0.0.1"
    ) -> List[Dict[str, Any]]:
        """
        List security events.
        
        GET /api/security/events
        
        Args:
            event_type: Filter by event type
            severity: Filter by severity
            limit: Maximum results
            auth_header: Authorization header
            ip_address: Client IP address
            
        Returns:
            List of events
        """
        self._check_auth_and_rate_limit(auth_header, ip_address)
        return self.service.list_events(
            event_type=event_type,
            severity=severity,
            limit=limit
        )
    
    def get_state(
        self,
        auth_header: Optional[str] = None,
        ip_address: str = "127.0.0.1"
    ) -> Dict[str, Any]:
        """
        Get current security state.
        
        GET /api/security/state
        
        Args:
            auth_header: Authorization header
            ip_address: Client IP address
            
        Returns:
            Security state
        """
        self._check_auth_and_rate_limit(auth_header, ip_address)
        
        state = self.service.get_security_state()
        
        return {
            "encryption_status": state.encryption_status,
            "mfa_active": state.mfa_active,
            "session_remaining_seconds": state.session_remaining_seconds,
            "threat_level": state.threat_level,
            "device_security_score": state.device_security_score,
            "active_alerts": state.active_alerts,
            "last_scan_timestamp": state.last_scan_timestamp
        }
    
    def get_threats(
        self,
        limit: int = 100,
        auth_header: Optional[str] = None,
        ip_address: str = "127.0.0.1"
    ) -> List[Dict[str, Any]]:
        """
        Get detected threats.
        
        GET /api/security/threats
        
        Args:
            limit: Maximum results
            auth_header: Authorization header
            ip_address: Client IP address
            
        Returns:
            List of threats
        """
        self._check_auth_and_rate_limit(auth_header, ip_address)
        
        threats = self.service.get_threats(limit=limit)
        
        return [
            {
                "threat_id": t.threat_id,
                "threat_type": t.threat_type,
                "severity": t.severity,
                "confidence_score": t.confidence_score,
                "first_detected": t.first_detected,
                "last_activity": t.last_activity,
                "status": t.status,
                "actions_taken": t.actions_taken
            }
            for t in threats
        ]
