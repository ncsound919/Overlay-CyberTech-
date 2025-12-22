"""
API routes for the backend.

Organizes endpoints by domain:
- Security events and state
- Security scanning
- SOAR playbooks
- System status and health
"""

from backend.routes.security import SecurityRoutes
from backend.routes.scan import ScanRoutes
from backend.routes.playbook import PlaybookRoutes
from backend.routes.system import SystemRoutes

__all__ = [
    "SecurityRoutes",
    "ScanRoutes",
    "PlaybookRoutes",
    "SystemRoutes",
]
