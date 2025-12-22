"""
System routes for the backend API.

Provides endpoints for:
- GET /api/health - Health check
- GET /api/status - System status
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from backend.middleware.auth import get_current_user
from backend.middleware.rate_limiter import check_rate_limit, RateLimitError


class SystemRoutes:
    """
    Route handlers for system endpoints.
    
    These endpoints are generally public (no auth required)
    but still rate-limited.
    """
    
    def __init__(self):
        """Initialize system routes."""
        self._start_time = datetime.now(timezone.utc)
        self._platform = None
    
    def _get_platform(self):
        """Lazy load the platform to avoid circular imports."""
        if self._platform is None:
            from main import OverlayCyberTech
            self._platform = OverlayCyberTech()
        return self._platform
    
    def health_check(
        self,
        ip_address: str = "127.0.0.1"
    ) -> Dict[str, Any]:
        """
        Health check endpoint.
        
        GET /api/health
        
        Args:
            ip_address: Client IP address
            
        Returns:
            Health status
        """
        # Rate limit health checks too (but with higher limits)
        allowed, retry_after = check_rate_limit(ip_address, None)
        if not allowed:
            raise RateLimitError("Rate limit exceeded", retry_after=retry_after)
        
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        
        # Check component health
        components = {
            "api": "healthy",
            "database": "healthy",
            "security_engine": "healthy"
        }
        
        # Verify platform is operational
        try:
            platform = self._get_platform()
            _ = platform.get_system_status()
        except Exception:
            components["security_engine"] = "degraded"
        
        # Determine overall status
        if all(s == "healthy" for s in components.values()):
            status = "healthy"
        elif any(s == "unhealthy" for s in components.values()):
            status = "unhealthy"
        else:
            status = "degraded"
        
        return {
            "status": status,
            "timestamp": timestamp,
            "components": components
        }
    
    def get_status(
        self,
        auth_header: Optional[str] = None,
        ip_address: str = "127.0.0.1"
    ) -> Dict[str, Any]:
        """
        Get detailed system status.
        
        GET /api/status
        
        Args:
            auth_header: Optional authorization header
            ip_address: Client IP address
            
        Returns:
            System status
        """
        # Rate limit
        allowed, retry_after = check_rate_limit(ip_address, None)
        if not allowed:
            raise RateLimitError("Rate limit exceeded", retry_after=retry_after)
        
        # Calculate uptime
        now = datetime.now(timezone.utc)
        uptime = (now - self._start_time).total_seconds()
        
        # Get platform status
        try:
            platform = self._get_platform()
            platform_status = platform.get_system_status()
        except Exception:
            platform_status = {
                "platform": {"os": "unknown", "hostname": "unknown"},
                "security": {"audit_log_entries": 0, "active_policies": 0}
            }
        
        # Check if user is authenticated for additional info
        user = get_current_user(auth_header)
        
        response = {
            "platform": platform_status.get("platform", {}),
            "security": platform_status.get("security", {}),
            "uptime_seconds": uptime,
            "version": "1.0.0"
        }
        
        # Add additional info for authenticated users
        if user:
            response["authenticated"] = True
            response["user"] = {
                "user_id": user.user_id,
                "username": user.username,
                "roles": user.roles
            }
        else:
            response["authenticated"] = False
        
        return response
    
    def get_version(self) -> Dict[str, Any]:
        """
        Get API version information.
        
        GET /api/version
        
        Returns:
            Version information
        """
        return {
            "api_version": "1.0.0",
            "platform_version": "1.0.0",
            "python_version": "3.8+"
        }
