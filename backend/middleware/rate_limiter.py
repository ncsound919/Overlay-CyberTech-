"""
Rate limiting middleware for the backend API.

Implements a token bucket algorithm with per-user and per-IP limits.
"""

import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from backend.config import get_config


@dataclass
class TokenBucket:
    """Token bucket for rate limiting."""
    capacity: int
    tokens: float
    refill_rate: float
    last_update: float = field(default_factory=time.time)
    
    def consume(self, tokens: int = 1) -> bool:
        """
        Attempt to consume tokens from the bucket.
        
        Args:
            tokens: Number of tokens to consume
            
        Returns:
            True if tokens were consumed, False if rate limited
        """
        now = time.time()
        elapsed = now - self.last_update
        
        # Refill tokens
        self.tokens = min(
            self.capacity,
            self.tokens + (elapsed * self.refill_rate)
        )
        self.last_update = now
        
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        
        return False
    
    def get_retry_after(self) -> float:
        """
        Calculate seconds until next token is available.
        
        Returns:
            Seconds until next token
        """
        if self.tokens >= 1:
            return 0.0
        
        tokens_needed = 1 - self.tokens
        return tokens_needed / self.refill_rate


class RateLimiter:
    """
    Rate limiter using token bucket algorithm.
    
    Supports per-user and per-IP rate limiting.
    """
    
    def __init__(
        self,
        capacity: Optional[int] = None,
        window_seconds: Optional[int] = None
    ):
        """
        Initialize the rate limiter.
        
        Args:
            capacity: Maximum requests per window (defaults to config)
            window_seconds: Window duration in seconds (defaults to config)
        """
        config = get_config()
        self.capacity = capacity or config.security.rate_limit_requests
        self.window_seconds = window_seconds or config.security.rate_limit_window_seconds
        self.refill_rate = self.capacity / self.window_seconds
        
        self._buckets: Dict[str, TokenBucket] = {}
        self._last_cleanup = time.time()
        self._cleanup_interval = 300  # Clean up every 5 minutes
    
    def _get_bucket(self, key: str) -> TokenBucket:
        """Get or create a bucket for the given key."""
        if key not in self._buckets:
            self._buckets[key] = TokenBucket(
                capacity=self.capacity,
                tokens=float(self.capacity),
                refill_rate=self.refill_rate
            )
        return self._buckets[key]
    
    def _cleanup_expired_buckets(self) -> None:
        """Remove buckets that haven't been used recently."""
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return
        
        self._last_cleanup = now
        expired_threshold = now - (self.window_seconds * 2)
        
        expired_keys = [
            key for key, bucket in self._buckets.items()
            if bucket.last_update < expired_threshold
        ]
        
        for key in expired_keys:
            del self._buckets[key]
    
    def is_allowed(self, key: str, tokens: int = 1) -> Tuple[bool, float]:
        """
        Check if a request is allowed.
        
        Args:
            key: Identifier for rate limiting (user_id, IP, etc.)
            tokens: Number of tokens to consume
            
        Returns:
            Tuple of (is_allowed, retry_after_seconds)
        """
        self._cleanup_expired_buckets()
        
        bucket = self._get_bucket(key)
        if bucket.consume(tokens):
            return True, 0.0
        
        return False, bucket.get_retry_after()
    
    def get_remaining(self, key: str) -> int:
        """
        Get remaining requests for the given key.
        
        Args:
            key: Identifier for rate limiting
            
        Returns:
            Number of remaining requests
        """
        if key not in self._buckets:
            return self.capacity
        
        bucket = self._buckets[key]
        
        # Update tokens without consuming
        now = time.time()
        elapsed = now - bucket.last_update
        current_tokens = min(
            self.capacity,
            bucket.tokens + (elapsed * self.refill_rate)
        )
        
        return int(current_tokens)


# Global rate limiter instances
_user_limiter: Optional[RateLimiter] = None
_ip_limiter: Optional[RateLimiter] = None


def _get_user_limiter() -> RateLimiter:
    """Get the user rate limiter instance."""
    global _user_limiter
    if _user_limiter is None:
        config = get_config()
        # Per-user limit: lower than global
        _user_limiter = RateLimiter(
            capacity=config.security.rate_limit_requests // 2,
            window_seconds=config.security.rate_limit_window_seconds
        )
    return _user_limiter


def _get_ip_limiter() -> RateLimiter:
    """Get the IP rate limiter instance."""
    global _ip_limiter
    if _ip_limiter is None:
        config = get_config()
        _ip_limiter = RateLimiter(
            capacity=config.security.rate_limit_requests,
            window_seconds=config.security.rate_limit_window_seconds
        )
    return _ip_limiter


class RateLimitError(Exception):
    """Raised when rate limit is exceeded."""
    
    def __init__(self, message: str, retry_after: float):
        super().__init__(message)
        self.retry_after = retry_after


def check_rate_limit(
    ip_address: str,
    user_id: Optional[str] = None
) -> Tuple[bool, float]:
    """
    Check rate limits for both IP and user.
    
    Args:
        ip_address: Client IP address
        user_id: Optional user identifier
        
    Returns:
        Tuple of (is_allowed, retry_after_seconds)
    """
    ip_limiter = _get_ip_limiter()
    user_limiter = _get_user_limiter()
    
    # Check IP limit
    ip_allowed, ip_retry = ip_limiter.is_allowed(f"ip:{ip_address}")
    if not ip_allowed:
        return False, ip_retry
    
    # Check user limit if authenticated
    if user_id:
        user_allowed, user_retry = user_limiter.is_allowed(f"user:{user_id}")
        if not user_allowed:
            return False, user_retry
    
    return True, 0.0
