"""
Playbook routes for the backend API.

Provides endpoints for:
- GET /api/playbooks - List playbooks
- GET /api/playbooks/{id} - Get playbook
- POST /api/playbooks/{id}/execute - Execute playbook
- GET /api/playbooks/executions - List executions
- GET /api/playbooks/executions/{id} - Get execution
"""

from typing import Any, Dict, List, Optional

from backend.middleware.auth import User, authenticate_request
from backend.middleware.rate_limiter import check_rate_limit, RateLimitError
from backend.models.schemas import PlaybookExecuteRequest
from backend.services.playbook_service import PlaybookService


class PlaybookRoutes:
    """
    Route handlers for playbook endpoints.
    
    Usage:
        routes = PlaybookRoutes()
        
        # List playbooks
        playbooks = routes.list_playbooks(auth_header, ip_address)
        
        # Execute playbook
        result = routes.execute_playbook(playbook_id, data, auth_header, ip_address)
    """
    
    def __init__(self, service: Optional[PlaybookService] = None):
        """
        Initialize playbook routes.
        
        Args:
            service: Optional PlaybookService instance
        """
        self.service = service or PlaybookService()
    
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
    
    def list_playbooks(
        self,
        auth_header: Optional[str] = None,
        ip_address: str = "127.0.0.1"
    ) -> List[Dict[str, Any]]:
        """
        List all available playbooks.
        
        GET /api/playbooks
        
        Args:
            auth_header: Authorization header
            ip_address: Client IP address
            
        Returns:
            List of playbooks
        """
        self._check_auth_and_rate_limit(auth_header, ip_address)
        return self.service.list_playbooks()
    
    def get_playbook(
        self,
        playbook_id: str,
        auth_header: Optional[str] = None,
        ip_address: str = "127.0.0.1"
    ) -> Optional[Dict[str, Any]]:
        """
        Get a playbook by ID.
        
        GET /api/playbooks/{playbook_id}
        
        Args:
            playbook_id: Playbook ID
            auth_header: Authorization header
            ip_address: Client IP address
            
        Returns:
            Playbook data or None
        """
        self._check_auth_and_rate_limit(auth_header, ip_address)
        return self.service.get_playbook(playbook_id)
    
    def execute_playbook(
        self,
        playbook_id: str,
        data: Dict[str, Any],
        auth_header: Optional[str] = None,
        ip_address: str = "127.0.0.1"
    ) -> Dict[str, Any]:
        """
        Execute a playbook.
        
        POST /api/playbooks/{playbook_id}/execute
        
        Args:
            playbook_id: Playbook ID
            data: Execution data
            auth_header: Authorization header
            ip_address: Client IP address
            
        Returns:
            Execution response
        """
        self._check_auth_and_rate_limit(auth_header, ip_address)
        
        request = PlaybookExecuteRequest(
            playbook_id=playbook_id,
            alert_id=data.get("alert_id", ""),
            context=data.get("context", {})
        )
        
        response = self.service.execute_playbook(request)
        
        return {
            "playbook_execution_id": response.playbook_execution_id,
            "playbook_id": response.playbook_id,
            "status": response.status,
            "actions_executed": response.actions_executed,
            "completion_time_seconds": response.completion_time_seconds
        }
    
    def get_execution(
        self,
        execution_id: str,
        auth_header: Optional[str] = None,
        ip_address: str = "127.0.0.1"
    ) -> Optional[Dict[str, Any]]:
        """
        Get an execution by ID.
        
        GET /api/playbooks/executions/{execution_id}
        
        Args:
            execution_id: Execution ID
            auth_header: Authorization header
            ip_address: Client IP address
            
        Returns:
            Execution data or None
        """
        self._check_auth_and_rate_limit(auth_header, ip_address)
        return self.service.get_execution(execution_id)
    
    def list_executions(
        self,
        playbook_id: Optional[str] = None,
        limit: int = 100,
        auth_header: Optional[str] = None,
        ip_address: str = "127.0.0.1"
    ) -> List[Dict[str, Any]]:
        """
        List playbook executions.
        
        GET /api/playbooks/executions
        
        Args:
            playbook_id: Optional filter by playbook
            limit: Maximum results
            auth_header: Authorization header
            ip_address: Client IP address
            
        Returns:
            List of executions
        """
        self._check_auth_and_rate_limit(auth_header, ip_address)
        return self.service.list_executions(
            playbook_id=playbook_id,
            limit=limit
        )
