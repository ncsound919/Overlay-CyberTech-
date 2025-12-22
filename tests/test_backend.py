"""
Tests for the backend API structure.

Tests cover:
- Configuration management
- Models and schemas
- Middleware (auth, rate limiting)
- Services
- Routes
- Application factory
"""

import pytest
import time

# Backend imports
from backend.config import Config, get_config, DatabaseConfig, SecurityConfig
from backend.models.schemas import (
    SecurityEventCreate, SecurityEventResponse, SecurityStateResponse,
    ScanRequest, PlaybookExecuteRequest,
    Severity, ThreatLevel
)
from backend.middleware.auth import (
    create_token, verify_token, authenticate_request, 
    get_current_user, User, AuthenticationError
)
from backend.middleware.rate_limiter import (
    RateLimiter, TokenBucket
)
from backend.services.security_service import SecurityService
from backend.services.scan_service import ScanService
from backend.services.playbook_service import PlaybookService
from backend.routes.security import SecurityRoutes
from backend.routes.system import SystemRoutes
from backend.app import BackendApp, create_app


# =============================================================================
# Configuration Tests
# =============================================================================

class TestConfiguration:
    """Tests for configuration management."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = Config()
        
        assert config.environment == "development"
        assert config.debug is False
        assert config.host == "0.0.0.0"
        assert config.port == 8000
    
    def test_database_config(self):
        """Test database configuration."""
        db_config = DatabaseConfig()
        
        assert "sqlite" in db_config.url
        assert db_config.pool_size == 5
        assert db_config.max_overflow == 10
    
    def test_security_config(self):
        """Test security configuration."""
        sec_config = SecurityConfig()
        
        assert sec_config.jwt_algorithm == "HS256"
        assert sec_config.jwt_expiration_hours == 24
        assert sec_config.rate_limit_requests == 100
        assert sec_config.rate_limit_window_seconds == 60
    
    def test_is_production(self):
        """Test production environment detection."""
        config = Config()
        assert config.is_production is False
        assert config.is_development is True
    
    def test_get_config(self):
        """Test get_config function."""
        config = get_config()
        assert isinstance(config, Config)


# =============================================================================
# Schema Tests
# =============================================================================

class TestSchemas:
    """Tests for request/response schemas."""
    
    def test_security_event_create(self):
        """Test SecurityEventCreate schema."""
        event = SecurityEventCreate(
            event_type="intrusion",
            severity="HIGH",
            detected_threat="Port scan detected",
            confidence_score=0.95,
            affected_asset="server-01"
        )
        
        assert event.event_type == "intrusion"
        assert event.severity == "HIGH"
        assert event.confidence_score == 0.95
    
    def test_security_event_response(self):
        """Test SecurityEventResponse schema."""
        response = SecurityEventResponse(
            event_id="EVT-123456",
            event_type="intrusion",
            severity="HIGH",
            timestamp="2024-01-01T00:00:00Z",
            audit_hash="abc123"
        )
        
        assert response.event_id == "EVT-123456"
        assert response.playbook_triggered is None
    
    def test_scan_request(self):
        """Test ScanRequest schema."""
        request = ScanRequest(detailed=True, auto_respond=True)
        
        assert request.scan_type == "full"
        assert request.detailed is True
        assert request.auto_respond is True
    
    def test_severity_enum(self):
        """Test Severity enum values."""
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"
    
    def test_threat_level_enum(self):
        """Test ThreatLevel enum values."""
        assert ThreatLevel.NONE.value == "NONE"
        assert ThreatLevel.CRITICAL.value == "CRITICAL"
    
    def test_security_event_validation_empty_fields(self):
        """Test SecurityEventCreate validates empty fields."""
        with pytest.raises(ValueError, match="must be a non-empty string"):
            SecurityEventCreate(
                event_type="",
                severity="HIGH",
                detected_threat="Test threat",
                confidence_score=0.5,
                affected_asset="server-01"
            )
    
    def test_security_event_validation_confidence_score(self):
        """Test SecurityEventCreate validates confidence_score range."""
        with pytest.raises(ValueError, match="between 0.0 and 1.0"):
            SecurityEventCreate(
                event_type="intrusion",
                severity="HIGH",
                detected_threat="Test threat",
                confidence_score=1.5,  # Invalid: > 1.0
                affected_asset="server-01"
            )


# =============================================================================
# Authentication Middleware Tests
# =============================================================================

class TestAuthMiddleware:
    """Tests for authentication middleware."""
    
    def test_create_token(self):
        """Test JWT token creation."""
        token = create_token(
            user_id="user-123",
            username="testuser",
            roles=["admin"],
            permissions=["read", "write"]
        )
        
        assert isinstance(token, str)
        assert len(token.split(".")) == 3  # JWT has 3 parts
    
    def test_verify_valid_token(self):
        """Test verification of valid token."""
        token = create_token(
            user_id="user-123",
            username="testuser"
        )
        
        is_valid, payload = verify_token(token)
        
        assert is_valid is True
        assert payload is not None
        assert payload["sub"] == "user-123"
        assert payload["username"] == "testuser"
    
    def test_verify_invalid_token(self):
        """Test verification of invalid token."""
        is_valid, payload = verify_token("invalid.token.here")
        
        assert is_valid is False
        assert payload is None
    
    def test_verify_tampered_token(self):
        """Test detection of tampered token."""
        import json
        import base64
        
        token = create_token(user_id="user-123", username="testuser")
        
        # Properly tamper by modifying the payload
        parts = token.split(".")
        
        # Decode payload, modify it, and re-encode
        # Add padding for base64 decoding
        payload_b64 = parts[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += '=' * padding
        payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode('utf-8'))
        payload["sub"] = "hacked-user"  # Modify the user ID
        modified_payload = base64.urlsafe_b64encode(
            json.dumps(payload).encode('utf-8')
        ).rstrip(b'=').decode('utf-8')
        
        tampered = f"{parts[0]}.{modified_payload}.{parts[2]}"
        
        is_valid, _ = verify_token(tampered)
        assert is_valid is False
    
    def test_authenticate_request_valid(self):
        """Test authenticating a valid request."""
        token = create_token(
            user_id="user-123",
            username="testuser",
            roles=["admin"]
        )
        
        user = authenticate_request(f"Bearer {token}")
        
        assert isinstance(user, User)
        assert user.user_id == "user-123"
        assert user.username == "testuser"
        assert "admin" in user.roles
    
    def test_authenticate_request_missing_header(self):
        """Test authentication with missing header."""
        with pytest.raises(AuthenticationError):
            authenticate_request(None)
    
    def test_authenticate_request_invalid_format(self):
        """Test authentication with invalid header format."""
        with pytest.raises(AuthenticationError):
            authenticate_request("InvalidFormat token")
    
    def test_get_current_user_success(self):
        """Test get_current_user with valid token."""
        token = create_token(user_id="user-123", username="testuser")
        
        user = get_current_user(f"Bearer {token}")
        
        assert user is not None
        assert user.user_id == "user-123"
    
    def test_get_current_user_failure(self):
        """Test get_current_user with invalid token."""
        user = get_current_user("Bearer invalid-token")
        assert user is None


# =============================================================================
# Rate Limiting Middleware Tests
# =============================================================================

class TestRateLimiterMiddleware:
    """Tests for rate limiting middleware."""
    
    def test_token_bucket_consume(self):
        """Test token bucket consumption."""
        bucket = TokenBucket(capacity=10, tokens=10.0, refill_rate=1.0)
        
        # Should allow consumption
        assert bucket.consume(1) is True
        assert bucket.consume(5) is True
        assert bucket.consume(4) is True
        
        # Should deny (only 0 tokens left)
        assert bucket.consume(1) is False
    
    def test_token_bucket_refill(self):
        """Test token bucket refilling."""
        bucket = TokenBucket(capacity=10, tokens=0.0, refill_rate=10.0)
        bucket.last_update = time.time() - 1  # 1 second ago
        
        # Should have refilled some tokens
        assert bucket.consume(5) is True
    
    def test_rate_limiter_is_allowed(self):
        """Test rate limiter allows requests."""
        limiter = RateLimiter(capacity=5, window_seconds=60)
        
        # First 5 requests should be allowed
        for i in range(5):
            allowed, retry_after = limiter.is_allowed(f"user:{i}")
            assert allowed is True
            assert retry_after == 0.0
    
    def test_rate_limiter_denies_excess(self):
        """Test rate limiter denies excess requests."""
        limiter = RateLimiter(capacity=3, window_seconds=60)
        
        # Exhaust all tokens
        for _ in range(3):
            limiter.is_allowed("user:1")
        
        # Next request should be denied
        allowed, retry_after = limiter.is_allowed("user:1")
        assert allowed is False
        assert retry_after > 0
    
    def test_rate_limiter_get_remaining(self):
        """Test getting remaining requests."""
        limiter = RateLimiter(capacity=10, window_seconds=60)
        
        # Should start with full capacity
        assert limiter.get_remaining("user:new") == 10
        
        # Use some tokens
        limiter.is_allowed("user:test")
        limiter.is_allowed("user:test")
        
        # Should have less remaining
        remaining = limiter.get_remaining("user:test")
        assert remaining == 8


# =============================================================================
# Service Tests
# =============================================================================

class TestSecurityService:
    """Tests for SecurityService."""
    
    def test_create_event(self):
        """Test creating a security event."""
        service = SecurityService()
        
        event = SecurityEventCreate(
            event_type="intrusion",
            severity="HIGH",
            detected_threat="Suspicious activity",
            confidence_score=0.85,
            affected_asset="server-01"
        )
        
        response = service.create_event(event)
        
        assert response.event_id.startswith("EVT-")
        assert response.event_type == "intrusion"
        assert response.severity == "HIGH"
        assert response.audit_hash is not None
    
    def test_get_event(self):
        """Test retrieving an event."""
        service = SecurityService()
        
        event = SecurityEventCreate(
            event_type="malware",
            severity="CRITICAL",
            detected_threat="Ransomware detected",
            confidence_score=0.99,
            affected_asset="workstation-05"
        )
        
        created = service.create_event(event)
        retrieved = service.get_event(created.event_id)
        
        assert retrieved is not None
        assert retrieved["event_id"] == created.event_id
    
    def test_get_security_state(self):
        """Test getting security state."""
        service = SecurityService()
        
        state = service.get_security_state()
        
        assert isinstance(state, SecurityStateResponse)
        assert state.encryption_status is True
        assert state.device_security_score >= 0
        assert state.device_security_score <= 100
    
    def test_list_events(self):
        """Test listing events."""
        service = SecurityService()
        
        # Create some events
        for i in range(3):
            event = SecurityEventCreate(
                event_type="intrusion",
                severity="MEDIUM",
                detected_threat=f"Threat {i}",
                confidence_score=0.5,
                affected_asset=f"asset-{i}"
            )
            service.create_event(event)
        
        events = service.list_events(limit=10)
        assert len(events) >= 3


class TestScanService:
    """Tests for ScanService."""
    
    def test_run_scan(self):
        """Test running a security scan."""
        service = ScanService()
        
        request = ScanRequest(
            scan_type="full",
            detailed=False,
            auto_respond=False
        )
        
        response = service.run_scan(request)
        
        assert response.scan_id.startswith("SCAN-")
        assert response.status in ["completed", "failed"]
        assert response.timestamp is not None
    
    def test_list_scans(self):
        """Test listing scans."""
        service = ScanService()
        
        # Run a scan
        request = ScanRequest()
        service.run_scan(request)
        
        scans = service.list_scans(limit=10)
        assert len(scans) >= 1


class TestPlaybookService:
    """Tests for PlaybookService."""
    
    def test_list_playbooks(self):
        """Test listing available playbooks."""
        service = PlaybookService()
        
        playbooks = service.list_playbooks()
        
        assert len(playbooks) > 0
        assert all("id" in pb for pb in playbooks)
        assert all("name" in pb for pb in playbooks)
    
    def test_get_playbook(self):
        """Test getting a specific playbook."""
        service = PlaybookService()
        
        playbook = service.get_playbook("incident_response_critical")
        
        assert playbook is not None
        assert playbook["id"] == "incident_response_critical"
        assert "steps" in playbook
    
    def test_execute_playbook(self):
        """Test executing a playbook."""
        service = PlaybookService()
        
        request = PlaybookExecuteRequest(
            playbook_id="incident_response_critical",
            alert_id="ALERT-123",
            context={"source_ip": "192.168.1.100"}
        )
        
        response = service.execute_playbook(request)
        
        assert response.playbook_execution_id.startswith("EXEC-")
        assert response.playbook_id == "incident_response_critical"
        assert response.status in ["completed", "partial_failure", "pending_approval"]
    
    def test_execute_nonexistent_playbook(self):
        """Test executing a non-existent playbook."""
        service = PlaybookService()
        
        request = PlaybookExecuteRequest(
            playbook_id="nonexistent",
            alert_id="ALERT-123"
        )
        
        response = service.execute_playbook(request)
        
        assert response.status == "failed"


# =============================================================================
# Route Tests
# =============================================================================

class TestSecurityRoutes:
    """Tests for SecurityRoutes."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.routes = SecurityRoutes()
        self.token = create_token(
            user_id="test-user",
            username="testuser",
            roles=["admin"]
        )
        self.auth_header = f"Bearer {self.token}"
    
    def test_create_event_authenticated(self):
        """Test creating event with authentication."""
        event_data = {
            "event_type": "intrusion",
            "severity": "HIGH",
            "detected_threat": "Port scan",
            "confidence_score": 0.9,
            "affected_asset": "firewall-01"
        }
        
        response = self.routes.create_event(
            event_data,
            auth_header=self.auth_header,
            ip_address="127.0.0.1"
        )
        
        assert "event_id" in response
        assert response["event_type"] == "intrusion"
    
    def test_create_event_unauthenticated(self):
        """Test creating event without authentication."""
        event_data = {"event_type": "test"}
        
        with pytest.raises(AuthenticationError):
            self.routes.create_event(event_data, auth_header=None)
    
    def test_get_state_authenticated(self):
        """Test getting security state."""
        state = self.routes.get_state(
            auth_header=self.auth_header,
            ip_address="127.0.0.1"
        )
        
        assert "encryption_status" in state
        assert "threat_level" in state


class TestSystemRoutes:
    """Tests for SystemRoutes."""
    
    def test_health_check(self):
        """Test health check endpoint."""
        routes = SystemRoutes()
        
        result = routes.health_check(ip_address="127.0.0.1")
        
        assert "status" in result
        assert "timestamp" in result
        assert "components" in result
    
    def test_get_version(self):
        """Test version endpoint."""
        routes = SystemRoutes()
        
        result = routes.get_version()
        
        assert "api_version" in result
        assert result["api_version"] == "1.0.0"


# =============================================================================
# Application Tests
# =============================================================================

class TestBackendApp:
    """Tests for BackendApp."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.app = create_app()
        self.token = create_token(
            user_id="test-user",
            username="testuser"
        )
    
    def test_create_app(self):
        """Test application factory."""
        app = create_app()
        
        assert isinstance(app, BackendApp)
        assert app.config is not None
    
    def test_health_endpoint(self):
        """Test health check endpoint."""
        status, response = self.app.handle_request("GET", "/api/health")
        
        assert status == 200
        assert response["status"] in ["healthy", "degraded", "unhealthy"]
    
    def test_version_endpoint(self):
        """Test version endpoint."""
        status, response = self.app.handle_request("GET", "/api/version")
        
        assert status == 200
        assert "api_version" in response
    
    def test_status_endpoint(self):
        """Test status endpoint."""
        status, response = self.app.handle_request("GET", "/api/status")
        
        assert status == 200
        assert "platform" in response
        assert "uptime_seconds" in response
    
    def test_authenticated_endpoint(self):
        """Test authenticated endpoint."""
        headers = {"Authorization": f"Bearer {self.token}"}
        
        status, response = self.app.handle_request(
            "GET", "/api/security/state",
            headers=headers
        )
        
        assert status == 200
        assert "threat_level" in response
    
    def test_unauthenticated_endpoint(self):
        """Test unauthenticated endpoint returns 401."""
        status, response = self.app.handle_request(
            "GET", "/api/security/events"
        )
        
        assert status == 401
        assert "error" in response
    
    def test_not_found_endpoint(self):
        """Test non-existent endpoint returns 404."""
        status, response = self.app.handle_request(
            "GET", "/api/nonexistent"
        )
        
        assert status == 404
        assert "error" in response
    
    def test_create_event_endpoint(self):
        """Test creating an event via API."""
        headers = {"Authorization": f"Bearer {self.token}"}
        body = {
            "event_type": "intrusion",
            "severity": "HIGH",
            "detected_threat": "Unauthorized access attempt",
            "confidence_score": 0.95,
            "affected_asset": "db-server"
        }
        
        status, response = self.app.handle_request(
            "POST", "/api/security/events",
            body=body,
            headers=headers
        )
        
        assert status == 201
        assert "event_id" in response
    
    def test_playbooks_endpoint(self):
        """Test listing playbooks."""
        headers = {"Authorization": f"Bearer {self.token}"}
        
        status, response = self.app.handle_request(
            "GET", "/api/playbooks",
            headers=headers
        )
        
        assert status == 200
        assert isinstance(response, list)
        assert len(response) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
