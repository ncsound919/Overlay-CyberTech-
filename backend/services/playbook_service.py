"""
Playbook service for SOAR automation.

Provides business logic for:
- Executing security playbooks
- Managing playbook definitions
- Tracking playbook execution history
"""

import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.models.schemas import PlaybookExecuteRequest, PlaybookExecuteResponse

# Module logger for audit failures
_logger = logging.getLogger(__name__)


# Predefined playbooks
PLAYBOOKS = {
    "incident_response_critical": {
        "id": "incident_response_critical",
        "name": "Critical Incident Response",
        "description": "Automated response for critical security incidents",
        "steps": [
            {"action": "ISOLATE_ENDPOINT", "type": "automatic"},
            {"action": "REVOKE_CREDENTIALS", "type": "automatic"},
            {"action": "BLOCK_IP_RANGE", "type": "automatic"},
            {"action": "ALERT_SECURITY_TEAM", "type": "automatic"},
            {"action": "TRIGGER_BACKUP", "type": "manual_approval"},
        ]
    },
    "incident_response_high": {
        "id": "incident_response_high",
        "name": "High Severity Response",
        "description": "Response for high severity security incidents",
        "steps": [
            {"action": "ISOLATE_ENDPOINT", "type": "automatic"},
            {"action": "MONITOR_ENHANCED", "type": "automatic"},
            {"action": "ALERT_SECURITY_TEAM", "type": "automatic"},
        ]
    },
    "ransomware_response": {
        "id": "ransomware_response",
        "name": "Ransomware Response",
        "description": "Automated response to ransomware detection",
        "steps": [
            {"action": "ISOLATE_DEVICE", "type": "automatic"},
            {"action": "REVOKE_CREDENTIALS", "type": "automatic"},
            {"action": "BLOCK_IP_RANGE", "type": "automatic"},
            {"action": "ALERT_SECURITY_TEAM", "type": "automatic"},
            {"action": "TRIGGER_BACKUP_RESTORE", "type": "manual_approval"},
        ]
    },
    "ddos_mitigation": {
        "id": "ddos_mitigation",
        "name": "DDoS Mitigation",
        "description": "Response to DDoS attacks",
        "steps": [
            {"action": "ENABLE_RATE_LIMITING", "type": "automatic"},
            {"action": "BLOCK_SUSPICIOUS_IPS", "type": "automatic"},
            {"action": "SCALE_INFRASTRUCTURE", "type": "automatic"},
            {"action": "ALERT_OPERATIONS", "type": "automatic"},
        ]
    },
    "data_breach_response": {
        "id": "data_breach_response",
        "name": "Data Breach Response",
        "description": "Response to potential data breach",
        "steps": [
            {"action": "ISOLATE_AFFECTED_SYSTEMS", "type": "automatic"},
            {"action": "PRESERVE_EVIDENCE", "type": "automatic"},
            {"action": "REVOKE_ALL_ACCESS", "type": "automatic"},
            {"action": "NOTIFY_LEGAL", "type": "automatic"},
            {"action": "NOTIFY_AFFECTED_USERS", "type": "manual_approval"},
        ]
    },
}


class PlaybookService:
    """
    Service for managing SOAR playbook operations.
    
    Provides execution, tracking, and management of security playbooks.
    """
    
    def __init__(self):
        """Initialize the playbook service."""
        self._executions: Dict[str, Dict[str, Any]] = {}
        self._platform = None
    
    def _get_platform(self):
        """Lazy load the platform to avoid circular imports."""
        if self._platform is None:
            from main import OverlayCyberTech
            self._platform = OverlayCyberTech()
        return self._platform
    
    def _generate_execution_id(self) -> str:
        """Generate a unique execution ID."""
        return f"EXEC-{uuid.uuid4().hex[:12].upper()}"
    
    def list_playbooks(self) -> List[Dict[str, Any]]:
        """
        List all available playbooks.
        
        Returns:
            List of playbook definitions
        """
        return [
            {
                "id": pb["id"],
                "name": pb["name"],
                "description": pb["description"],
                "step_count": len(pb["steps"])
            }
            for pb in PLAYBOOKS.values()
        ]
    
    def get_playbook(self, playbook_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a playbook by ID.
        
        Args:
            playbook_id: The playbook ID
            
        Returns:
            Playbook definition or None
        """
        return PLAYBOOKS.get(playbook_id)
    
    def execute_playbook(self, request: PlaybookExecuteRequest) -> PlaybookExecuteResponse:
        """
        Execute a security playbook.
        
        Args:
            request: Playbook execution request
            
        Returns:
            Execution response with results
        """
        execution_id = self._generate_execution_id()
        start_time = time.time()
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        
        playbook = PLAYBOOKS.get(request.playbook_id)
        
        if not playbook:
            return PlaybookExecuteResponse(
                playbook_execution_id=execution_id,
                playbook_id=request.playbook_id,
                status="failed",
                actions_executed=[{
                    "action": "PLAYBOOK_LOOKUP",
                    "status": "failed",
                    "reason": f"Playbook '{request.playbook_id}' not found"
                }],
                completion_time_seconds=time.time() - start_time
            )
        
        execution_data = {
            "execution_id": execution_id,
            "playbook_id": request.playbook_id,
            "alert_id": request.alert_id,
            "context": request.context,
            "timestamp": timestamp,
            "status": "running",
            "actions": []
        }
        
        self._executions[execution_id] = execution_data
        
        actions_executed = []
        
        # Execute each step
        for step in playbook["steps"]:
            action = step["action"]
            action_type = step["type"]
            
            action_result = {
                "action": action,
                "type": action_type,
                "status": "pending"
            }
            
            if action_type == "automatic":
                # Execute automatic actions
                success = self._execute_action(action, request.context)
                action_result["status"] = "success" if success else "failed"
            else:
                # Manual approval required
                action_result["status"] = "pending_approval"
                action_result["approval_required"] = True
            
            actions_executed.append(action_result)
            execution_data["actions"].append(action_result)
        
        # Determine overall status
        failed_count = sum(1 for a in actions_executed if a["status"] == "failed")
        pending_count = sum(1 for a in actions_executed if a["status"] == "pending_approval")
        
        if failed_count > 0:
            execution_data["status"] = "partial_failure"
        elif pending_count > 0:
            execution_data["status"] = "pending_approval"
        else:
            execution_data["status"] = "completed"
        
        completion_time = time.time() - start_time
        execution_data["completion_time_seconds"] = completion_time
        
        # Log to audit trail
        try:
            platform = self._get_platform()
            platform.audit_log.append({
                "event_id": execution_id,
                "event_type": "PLAYBOOK_EXECUTION",
                "playbook_id": request.playbook_id,
                "status": execution_data["status"],
                "data": execution_data
            })
        except Exception as e:
            # Log audit failure so administrators are aware
            _logger.warning(f"Failed to log playbook execution {execution_id} to audit trail: {e}")
        
        return PlaybookExecuteResponse(
            playbook_execution_id=execution_id,
            playbook_id=request.playbook_id,
            status=execution_data["status"],
            actions_executed=[
                {"action": a["action"], "status": a["status"]}
                for a in actions_executed
            ],
            completion_time_seconds=completion_time
        )
    
    def _execute_action(self, action: str, context: Dict[str, Any]) -> bool:
        """
        Execute a single playbook action.
        
        Args:
            action: Action name
            context: Execution context
            
        Returns:
            True if successful, False otherwise
        """
        # Map actions to platform operations using a dispatch table
        # In production, these would call actual platform methods
        action_handlers = {
            "ISOLATE_ENDPOINT": lambda p, c: True,
            "ISOLATE_DEVICE": lambda p, c: True,
            "REVOKE_CREDENTIALS": lambda p, c: True,
            "BLOCK_IP_RANGE": lambda p, c: True,
            "ALERT_SECURITY_TEAM": lambda p, c: True,
            "MONITOR_ENHANCED": lambda p, c: True,
            "ENABLE_RATE_LIMITING": lambda p, c: True,
            "BLOCK_SUSPICIOUS_IPS": lambda p, c: True,
            "SCALE_INFRASTRUCTURE": lambda p, c: True,
            "ALERT_OPERATIONS": lambda p, c: True,
            "ISOLATE_AFFECTED_SYSTEMS": lambda p, c: True,
            "PRESERVE_EVIDENCE": lambda p, c: True,
            "REVOKE_ALL_ACCESS": lambda p, c: True,
            "NOTIFY_LEGAL": lambda p, c: True,
        }
        
        try:
            handler = action_handlers.get(action)
            if handler is None:
                # Unknown action
                return False
            
            platform = self._get_platform()
            return handler(platform, context)
        except Exception:
            return False
    
    def get_execution(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """
        Get an execution by ID.
        
        Args:
            execution_id: The execution ID
            
        Returns:
            Execution data or None
        """
        return self._executions.get(execution_id)
    
    def list_executions(
        self,
        playbook_id: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        List playbook executions.
        
        Args:
            playbook_id: Optional filter by playbook ID
            limit: Maximum results to return
            
        Returns:
            List of execution data
        """
        executions = list(self._executions.values())
        
        if playbook_id:
            executions = [e for e in executions if e.get("playbook_id") == playbook_id]
        
        # Sort by timestamp descending
        executions.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
        
        return executions[:limit]
