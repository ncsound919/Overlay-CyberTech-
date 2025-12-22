"""
Authentication middleware for the backend API.

Provides JWT-based authentication with secure token handling.
"""

import hashlib
import hmac
import json
import time
import base64
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from backend.config import get_config


@dataclass
class User:
    """Represents an authenticated user."""
    user_id: str
    username: str
    roles: list
    permissions: list


class AuthenticationError(Exception):
    """Raised when authentication fails."""
    pass


def _base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url string without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def _base64url_decode(data: str) -> bytes:
    """Decode base64url string to bytes."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)


def create_token(user_id: str, username: str, roles: list = None, 
                 permissions: list = None) -> str:
    """
    Create a JWT token for the given user.
    
    Args:
        user_id: Unique identifier for the user
        username: User's username
        roles: List of user roles
        permissions: List of user permissions
        
    Returns:
        JWT token string
    """
    config = get_config()
    
    # Header
    header = {
        "alg": config.security.jwt_algorithm,
        "typ": "JWT"
    }
    
    # Payload
    current_time = int(time.time())
    expiration = current_time + (config.security.jwt_expiration_hours * 3600)
    
    payload = {
        "sub": user_id,
        "username": username,
        "roles": roles or [],
        "permissions": permissions or [],
        "iat": current_time,
        "exp": expiration
    }
    
    # Encode header and payload
    header_encoded = _base64url_encode(json.dumps(header).encode('utf-8'))
    payload_encoded = _base64url_encode(json.dumps(payload).encode('utf-8'))
    
    # Create signature
    message = f"{header_encoded}.{payload_encoded}"
    signature = hmac.new(
        config.security.secret_key.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).digest()
    signature_encoded = _base64url_encode(signature)
    
    return f"{header_encoded}.{payload_encoded}.{signature_encoded}"


def verify_token(token: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Verify a JWT token and return its payload.
    
    Args:
        token: JWT token string
        
    Returns:
        Tuple of (is_valid, payload_or_none)
    """
    config = get_config()
    
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return False, None
        
        header_encoded, payload_encoded, signature_encoded = parts
        
        # Verify signature
        message = f"{header_encoded}.{payload_encoded}"
        expected_signature = hmac.new(
            config.security.secret_key.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).digest()
        
        actual_signature = _base64url_decode(signature_encoded)
        
        # Use constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(expected_signature, actual_signature):
            return False, None
        
        # Decode payload
        payload = json.loads(_base64url_decode(payload_encoded).decode('utf-8'))
        
        # Check expiration
        if payload.get('exp', 0) < time.time():
            return False, None
        
        return True, payload
        
    except Exception:
        return False, None


def authenticate_request(authorization_header: Optional[str]) -> User:
    """
    Authenticate a request using the Authorization header.
    
    Args:
        authorization_header: The Authorization header value
        
    Returns:
        Authenticated User object
        
    Raises:
        AuthenticationError: If authentication fails
    """
    if not authorization_header:
        raise AuthenticationError("Missing authorization header")
    
    parts = authorization_header.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        raise AuthenticationError("Invalid authorization header format")
    
    token = parts[1]
    is_valid, payload = verify_token(token)
    
    if not is_valid or payload is None:
        raise AuthenticationError("Invalid or expired token")
    
    return User(
        user_id=payload.get('sub', ''),
        username=payload.get('username', ''),
        roles=payload.get('roles', []),
        permissions=payload.get('permissions', [])
    )


def get_current_user(authorization_header: Optional[str]) -> Optional[User]:
    """
    Get the current user from the authorization header without raising exceptions.
    
    Args:
        authorization_header: The Authorization header value
        
    Returns:
        User object if authenticated, None otherwise
    """
    try:
        return authenticate_request(authorization_header)
    except AuthenticationError:
        return None
