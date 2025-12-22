"""
Scan service for managing security scans.

Provides business logic for:
- Initiating security scans
- Retrieving scan results
- Managing scan queue
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.models.schemas import ScanRequest, ScanResponse


class ScanService:
    """
    Service for managing security scan operations.
    
    Integrates with the core platform for threat detection.
    """
    
    def __init__(self):
        """Initialize the scan service."""
        self._scans: Dict[str, Dict[str, Any]] = {}
        self._platform = None
    
    def _get_platform(self):
        """Lazy load the platform to avoid circular imports."""
        if self._platform is None:
            from main import OverlayCyberTech
            self._platform = OverlayCyberTech()
        return self._platform
    
    def _generate_scan_id(self) -> str:
        """Generate a unique scan ID."""
        return f"SCAN-{uuid.uuid4().hex[:12].upper()}"
    
    def run_scan(self, request: ScanRequest) -> ScanResponse:
        """
        Run a security scan.
        
        Args:
            request: Scan request parameters
            
        Returns:
            Scan response with results
        """
        scan_id = self._generate_scan_id()
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        
        scan_data = {
            "scan_id": scan_id,
            "timestamp": timestamp,
            "target_path": request.target_path,
            "scan_type": request.scan_type,
            "detailed": request.detailed,
            "status": "running"
        }
        
        self._scans[scan_id] = scan_data
        
        try:
            # Run actual scan using platform
            platform = self._get_platform()
            results = platform.run_security_scan(detailed=request.detailed)
            
            # Update scan data with results
            scan_data.update({
                "status": "completed",
                "threats_detected": results.get("intrusion_detection", {}).get("threats_detected", 0),
                "intruders_found": results.get("intrusion_detection", {}).get("intruders_found", 0),
                "risk_level": results.get("intrusion_detection", {}).get("risk_level", "LOW"),
                "recommendations": results.get("intrusion_detection", {}).get("recommendations", []),
                "attack_statistics": results.get("attack_statistics", {}),
            })
            
            if request.detailed:
                scan_data["details"] = {
                    "intruders": results.get("intruders", []),
                    "attack_statistics": results.get("attack_statistics", {})
                }
            
            # Auto-respond if requested
            if request.auto_respond and scan_data["threats_detected"] > 0:
                response_results = platform.respond_to_threats(auto_freeze=True)
                scan_data["response_actions"] = response_results
            
        except Exception as e:
            scan_data["status"] = "failed"
            scan_data["error"] = str(e)
            scan_data["threats_detected"] = 0
            scan_data["intruders_found"] = 0
            scan_data["risk_level"] = "UNKNOWN"
            scan_data["recommendations"] = []
            # Remove failed scan from in-memory storage to prevent unbounded growth
            self._scans.pop(scan_id, None)
        
        return ScanResponse(
            scan_id=scan_data["scan_id"],
            status=scan_data["status"],
            timestamp=scan_data["timestamp"],
            threats_detected=scan_data.get("threats_detected", 0),
            intruders_found=scan_data.get("intruders_found", 0),
            risk_level=scan_data.get("risk_level", "UNKNOWN"),
            recommendations=scan_data.get("recommendations", []),
            details=scan_data.get("details")
        )
    
    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a scan by ID.
        
        Args:
            scan_id: The scan ID
            
        Returns:
            Scan data or None if not found
        """
        return self._scans.get(scan_id)
    
    def list_scans(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        List all scans.
        
        Args:
            limit: Maximum number of scans to return
            
        Returns:
            List of scan data
        """
        scans = list(self._scans.values())
        
        # Sort by timestamp descending
        scans.sort(key=lambda s: s.get("timestamp", ""), reverse=True)
        
        return scans[:limit]
    
    def run_cleanup_preview(self) -> Dict[str, Any]:
        """
        Run a cleanup preview scan.
        
        Returns:
            Cleanup preview results
        """
        try:
            platform = self._get_platform()
            preview = platform.run_system_cleanup(dry_run=True)
            return {
                "status": "success",
                "total_bytes_freed_mb": preview.get("total_bytes_freed_mb", 0),
                "total_files_deleted": preview.get("total_files_deleted", 0),
                "results_by_category": preview.get("results_by_category", [])
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }
    
    def run_disk_analysis(self, path: Optional[str] = None) -> Dict[str, Any]:
        """
        Run disk usage analysis.
        
        Args:
            path: Optional path to analyze
            
        Returns:
            Disk usage analysis results
        """
        try:
            platform = self._get_platform()
            usage = platform.analyze_disk_usage(path=path)
            return {
                "status": "success",
                **usage
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }
