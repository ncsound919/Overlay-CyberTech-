"""
Scan routes for the backend API.

Provides endpoints for:
- POST /api/scan - Run security scan
- GET /api/scan/{id} - Get scan results
- GET /api/scan - List scans
- GET /api/scan/cleanup - Get cleanup preview
- GET /api/scan/disk - Get disk analysis
"""

from typing import Any, Dict, List, Optional

from backend.middleware.auth import User, authenticate_request
from backend.middleware.rate_limiter import check_rate_limit, RateLimitError
from backend.models.schemas import ScanRequest, ScanResponse
from backend.services.scan_service import ScanService


class ScanRoutes:
    """
    Route handlers for scan endpoints.
    
    Usage:
        routes = ScanRoutes()
        
        # Run scan
        response = routes.run_scan(scan_data, auth_header, ip_address)
    """
    
    def __init__(self, service: Optional[ScanService] = None):
        """
        Initialize scan routes.
        
        Args:
            service: Optional ScanService instance
        """
        self.service = service or ScanService()
    
    def _check_auth_and_rate_limit(
        self,
        auth_header: Optional[str],
        ip_address: str
    ) -> User:
        """Check authentication and rate limits."""
        user = authenticate_request(auth_header)
        
        allowed, retry_after = check_rate_limit(ip_address, user.user_id)
        if not allowed:
            raise RateLimitError(
                "Rate limit exceeded",
                retry_after=retry_after
            )
        
        return user
    
    def run_scan(
        self,
        scan_data: Dict[str, Any],
        auth_header: Optional[str] = None,
        ip_address: str = "127.0.0.1"
    ) -> Dict[str, Any]:
        """
        Run a security scan.
        
        POST /api/scan
        
        Args:
            scan_data: Scan parameters
            auth_header: Authorization header
            ip_address: Client IP address
            
        Returns:
            Scan response
        """
        self._check_auth_and_rate_limit(auth_header, ip_address)
        
        request = ScanRequest(
            target_path=scan_data.get("target_path"),
            scan_type=scan_data.get("scan_type", "full"),
            detailed=scan_data.get("detailed", False),
            auto_respond=scan_data.get("auto_respond", False)
        )
        
        response = self.service.run_scan(request)
        
        return {
            "scan_id": response.scan_id,
            "status": response.status,
            "timestamp": response.timestamp,
            "threats_detected": response.threats_detected,
            "intruders_found": response.intruders_found,
            "risk_level": response.risk_level,
            "recommendations": response.recommendations,
            "details": response.details
        }
    
    def get_scan(
        self,
        scan_id: str,
        auth_header: Optional[str] = None,
        ip_address: str = "127.0.0.1"
    ) -> Optional[Dict[str, Any]]:
        """
        Get scan results by ID.
        
        GET /api/scan/{scan_id}
        
        Args:
            scan_id: Scan ID
            auth_header: Authorization header
            ip_address: Client IP address
            
        Returns:
            Scan data or None
        """
        self._check_auth_and_rate_limit(auth_header, ip_address)
        return self.service.get_scan(scan_id)
    
    def list_scans(
        self,
        limit: int = 100,
        auth_header: Optional[str] = None,
        ip_address: str = "127.0.0.1"
    ) -> List[Dict[str, Any]]:
        """
        List all scans.
        
        GET /api/scan
        
        Args:
            limit: Maximum results
            auth_header: Authorization header
            ip_address: Client IP address
            
        Returns:
            List of scans
        """
        self._check_auth_and_rate_limit(auth_header, ip_address)
        return self.service.list_scans(limit=limit)
    
    def get_cleanup_preview(
        self,
        auth_header: Optional[str] = None,
        ip_address: str = "127.0.0.1"
    ) -> Dict[str, Any]:
        """
        Get cleanup preview.
        
        GET /api/scan/cleanup
        
        Args:
            auth_header: Authorization header
            ip_address: Client IP address
            
        Returns:
            Cleanup preview results
        """
        self._check_auth_and_rate_limit(auth_header, ip_address)
        return self.service.run_cleanup_preview()
    
    def get_disk_analysis(
        self,
        path: Optional[str] = None,
        auth_header: Optional[str] = None,
        ip_address: str = "127.0.0.1"
    ) -> Dict[str, Any]:
        """
        Get disk usage analysis.
        
        GET /api/scan/disk
        
        Args:
            path: Optional path to analyze
            auth_header: Authorization header
            ip_address: Client IP address
            
        Returns:
            Disk analysis results
        """
        self._check_auth_and_rate_limit(auth_header, ip_address)
        return self.service.run_disk_analysis(path=path)
