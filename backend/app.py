"""
Main application entry point for the backend API.

This module provides:
- Application factory for creating the API app
- Request handling and routing
- Error handling and logging
- A simple HTTP server for development

For production, use a proper WSGI/ASGI server like Gunicorn or Uvicorn.
"""

import json
import logging
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from backend.config import get_config, Config
from backend.middleware.auth import AuthenticationError
from backend.middleware.rate_limiter import RateLimitError
from backend.routes import SecurityRoutes, ScanRoutes, PlaybookRoutes, SystemRoutes


# Configure logging
def setup_logging(config: Config) -> logging.Logger:
    """Setup logging based on configuration."""
    logger = logging.getLogger("overlay_cybertech")
    logger.setLevel(getattr(logging, config.logging.level))
    
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(getattr(logging, config.logging.level))
    
    if config.logging.json_format:
        # JSON format for structured logging
        formatter = logging.Formatter(
            '{"timestamp": "%(asctime)s", "level": "%(levelname)s", '
            '"logger": "%(name)s", "message": "%(message)s"}'
        )
    else:
        formatter = logging.Formatter(config.logging.format)
    
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    
    return logger


class BackendApp:
    """
    Main backend application class.
    
    Provides a unified interface for handling API requests.
    """
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize the backend application.
        
        Args:
            config: Optional configuration object
        """
        self.config = config or get_config()
        self.logger = setup_logging(self.config)
        
        # Initialize route handlers
        self.security_routes = SecurityRoutes()
        self.scan_routes = ScanRoutes()
        self.playbook_routes = PlaybookRoutes()
        self.system_routes = SystemRoutes()
        
        self.logger.info(
            f"Backend initialized in {self.config.environment} mode"
        )
    
    def handle_request(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        query_params: Optional[Dict[str, str]] = None,
        ip_address: str = "127.0.0.1"
    ) -> Tuple[int, Dict[str, Any]]:
        """
        Handle an incoming API request.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            path: Request path
            body: Request body (for POST/PUT)
            headers: Request headers
            query_params: Query parameters
            ip_address: Client IP address
            
        Returns:
            Tuple of (status_code, response_body)
        """
        headers = headers or {}
        body = body or {}
        query_params = query_params or {}
        
        auth_header = headers.get("Authorization") or headers.get("authorization")
        
        try:
            # Route the request
            return self._route_request(
                method, path, body, auth_header, query_params, ip_address
            )
        
        except AuthenticationError as e:
            return 401, {
                "error": "Unauthorized",
                "message": str(e)
            }
        
        except RateLimitError as e:
            return 429, {
                "error": "Too Many Requests",
                "message": str(e),
                "retry_after": e.retry_after
            }
        
        except Exception as e:
            self.logger.error(f"Request error: {e}", exc_info=True)
            return 500, {
                "error": "Internal Server Error",
                "message": str(e) if self.config.debug else "An error occurred"
            }
    
    def _route_request(
        self,
        method: str,
        path: str,
        body: Dict[str, Any],
        auth_header: Optional[str],
        query_params: Dict[str, str],
        ip_address: str
    ) -> Tuple[int, Dict[str, Any]]:
        """Route request to appropriate handler."""
        
        # Strip trailing slash
        path = path.rstrip("/")
        
        # Helper to parse limit parameter with validation
        def parse_limit(default: int = 100) -> Tuple[Optional[int], Optional[Tuple[int, Dict[str, Any]]]]:
            """Parse and validate limit parameter. Returns (value, error_response)."""
            limit_param = query_params.get("limit")
            if limit_param is None:
                return default, None
            try:
                value = int(limit_param)
                if value < 1:
                    return None, (400, {
                        "error": "Bad Request",
                        "message": "Invalid 'limit' parameter; must be a positive integer."
                    })
                if value > 1000:
                    value = 1000  # Cap at reasonable maximum
                return value, None
            except ValueError:
                return None, (400, {
                    "error": "Bad Request",
                    "message": "Invalid 'limit' parameter; must be an integer."
                })
        
        # Health check (no auth required)
        if path == "/api/health" and method == "GET":
            return 200, self.system_routes.health_check(ip_address)
        
        # Version (no auth required)
        if path == "/api/version" and method == "GET":
            return 200, self.system_routes.get_version()
        
        # Status
        if path == "/api/status" and method == "GET":
            return 200, self.system_routes.get_status(auth_header, ip_address)
        
        # Security events
        if path == "/api/security/events":
            if method == "GET":
                limit, error = parse_limit()
                if error:
                    return error
                return 200, self.security_routes.list_events(
                    event_type=query_params.get("event_type"),
                    severity=query_params.get("severity"),
                    limit=limit,
                    auth_header=auth_header,
                    ip_address=ip_address
                )
            elif method == "POST":
                result = self.security_routes.create_event(
                    body, auth_header, ip_address
                )
                return 201, result
        
        if path.startswith("/api/security/events/") and method == "GET":
            event_id = path.split("/")[-1]
            result = self.security_routes.get_event(
                event_id, auth_header, ip_address
            )
            if result:
                return 200, result
            return 404, {"error": "Not Found", "message": f"Event {event_id} not found"}
        
        # Security state
        if path == "/api/security/state" and method == "GET":
            return 200, self.security_routes.get_state(auth_header, ip_address)
        
        # Threats
        if path == "/api/security/threats" and method == "GET":
            limit, error = parse_limit()
            if error:
                return error
            return 200, self.security_routes.get_threats(
                limit=limit,
                auth_header=auth_header,
                ip_address=ip_address
            )
        
        # Scans
        if path == "/api/scan":
            if method == "GET":
                limit, error = parse_limit()
                if error:
                    return error
                return 200, self.scan_routes.list_scans(
                    limit=limit,
                    auth_header=auth_header,
                    ip_address=ip_address
                )
            elif method == "POST":
                result = self.scan_routes.run_scan(body, auth_header, ip_address)
                return 201, result
        
        if path.startswith("/api/scan/") and method == "GET":
            if path == "/api/scan/cleanup":
                return 200, self.scan_routes.get_cleanup_preview(
                    auth_header, ip_address
                )
            elif path == "/api/scan/disk":
                return 200, self.scan_routes.get_disk_analysis(
                    path=query_params.get("path"),
                    auth_header=auth_header,
                    ip_address=ip_address
                )
            else:
                scan_id = path.split("/")[-1]
                result = self.scan_routes.get_scan(scan_id, auth_header, ip_address)
                if result:
                    return 200, result
                return 404, {"error": "Not Found", "message": f"Scan {scan_id} not found"}
        
        # Playbooks
        if path == "/api/playbooks" and method == "GET":
            return 200, self.playbook_routes.list_playbooks(auth_header, ip_address)
        
        if path == "/api/playbooks/executions" and method == "GET":
            limit, error = parse_limit()
            if error:
                return error
            return 200, self.playbook_routes.list_executions(
                playbook_id=query_params.get("playbook_id"),
                limit=limit,
                auth_header=auth_header,
                ip_address=ip_address
            )
        
        if path.startswith("/api/playbooks/executions/") and method == "GET":
            execution_id = path.split("/")[-1]
            result = self.playbook_routes.get_execution(
                execution_id, auth_header, ip_address
            )
            if result:
                return 200, result
            return 404, {"error": "Not Found", "message": f"Execution {execution_id} not found"}
        
        if path.startswith("/api/playbooks/") and "/execute" in path and method == "POST":
            parts = path.split("/")
            playbook_id = parts[-2]
            result = self.playbook_routes.execute_playbook(
                playbook_id, body, auth_header, ip_address
            )
            return 201, result
        
        if path.startswith("/api/playbooks/") and method == "GET":
            playbook_id = path.split("/")[-1]
            result = self.playbook_routes.get_playbook(
                playbook_id, auth_header, ip_address
            )
            if result:
                return 200, result
            return 404, {"error": "Not Found", "message": f"Playbook {playbook_id} not found"}
        
        # Not found
        return 404, {"error": "Not Found", "message": f"Endpoint {method} {path} not found"}


class APIRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the development server."""
    
    app: BackendApp = None  # Set by the server
    
    def _get_client_ip(self) -> str:
        """Get client IP address."""
        forwarded = self.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return self.client_address[0]
    
    def _send_json_response(self, status: int, data: Dict[str, Any]) -> None:
        """Send a JSON response."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str).encode())
    
    def _parse_query_params(self, path: str) -> Tuple[str, Dict[str, str]]:
        """Parse query parameters from path."""
        parsed = urlparse(path)
        query_params = {}
        if parsed.query:
            for key, values in parse_qs(parsed.query).items():
                query_params[key] = values[0] if values else ""
        return parsed.path, query_params
    
    def _read_body(self) -> Dict[str, Any]:
        """Read and parse JSON body."""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            return {}
        
        body = self.rfile.read(content_length)
        try:
            return json.loads(body.decode())
        except json.JSONDecodeError:
            return {}
    
    def do_GET(self) -> None:
        """Handle GET requests."""
        path, query_params = self._parse_query_params(self.path)
        headers = dict(self.headers)
        
        status, response = self.app.handle_request(
            "GET", path, None, headers, query_params, self._get_client_ip()
        )
        self._send_json_response(status, response)
    
    def do_POST(self) -> None:
        """Handle POST requests."""
        path, query_params = self._parse_query_params(self.path)
        headers = dict(self.headers)
        body = self._read_body()
        
        status, response = self.app.handle_request(
            "POST", path, body, headers, query_params, self._get_client_ip()
        )
        self._send_json_response(status, response)
    
    def do_OPTIONS(self) -> None:
        """Handle OPTIONS requests (CORS preflight)."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()
    
    def log_message(self, format: str, *args) -> None:
        """Override to use our logger."""
        if self.app:
            self.app.logger.info(f"{self._get_client_ip()} - {format % args}")


def create_app(config: Optional[Config] = None) -> BackendApp:
    """
    Application factory for creating the backend app.
    
    Args:
        config: Optional configuration object
        
    Returns:
        Configured BackendApp instance
    """
    return BackendApp(config)


def run_development_server(
    host: str = "0.0.0.0",
    port: int = 8000,
    config: Optional[Config] = None
) -> None:
    """
    Run the development HTTP server.
    
    Args:
        host: Host to bind to
        port: Port to listen on
        config: Optional configuration object
    """
    app = create_app(config)
    APIRequestHandler.app = app
    
    server = HTTPServer((host, port), APIRequestHandler)
    
    print(f"=" * 70)
    print(f"Overlay-CyberTech Backend API Server")
    print(f"=" * 70)
    print(f"Server running at http://{host}:{port}")
    print(f"Environment: {app.config.environment}")
    print(f"Debug mode: {app.config.debug}")
    print(f"")
    print(f"Available endpoints:")
    print(f"  GET  /api/health           - Health check")
    print(f"  GET  /api/version          - API version")
    print(f"  GET  /api/status           - System status")
    print(f"  GET  /api/security/events  - List security events")
    print(f"  POST /api/security/events  - Create security event")
    print(f"  GET  /api/security/state   - Get security state")
    print(f"  GET  /api/security/threats - Get detected threats")
    print(f"  GET  /api/scan             - List scans")
    print(f"  POST /api/scan             - Run security scan")
    print(f"  GET  /api/playbooks        - List playbooks")
    print(f"  POST /api/playbooks/{{id}}/execute - Execute playbook")
    print(f"")
    print(f"Press Ctrl+C to stop")
    print(f"=" * 70)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


if __name__ == "__main__":
    run_development_server()
