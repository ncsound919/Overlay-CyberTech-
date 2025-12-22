"""
Configuration management for the backend API.

Handles environment-based configuration with sensible defaults.
"""

import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DatabaseConfig:
    """Database configuration settings."""
    url: str = field(default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///./overlay_cybertech.db"))
    pool_size: int = field(default_factory=lambda: int(os.getenv("DATABASE_POOL_SIZE", "5")))
    max_overflow: int = field(default_factory=lambda: int(os.getenv("DATABASE_MAX_OVERFLOW", "10")))


@dataclass
class SecurityConfig:
    """Security-related configuration."""
    secret_key: str = field(default_factory=lambda: os.getenv("SECRET_KEY", "change-me-in-production"))
    jwt_algorithm: str = "HS256"
    jwt_expiration_hours: int = field(default_factory=lambda: int(os.getenv("JWT_EXPIRATION_HOURS", "24")))
    rate_limit_requests: int = field(default_factory=lambda: int(os.getenv("RATE_LIMIT_REQUESTS", "100")))
    rate_limit_window_seconds: int = field(default_factory=lambda: int(os.getenv("RATE_LIMIT_WINDOW", "60")))


@dataclass
class LoggingConfig:
    """Logging configuration."""
    level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    json_format: bool = field(default_factory=lambda: os.getenv("LOG_JSON", "false").lower() == "true")


@dataclass
class Config:
    """Main application configuration."""
    environment: str = field(default_factory=lambda: os.getenv("ENVIRONMENT", "development"))
    debug: bool = field(default_factory=lambda: os.getenv("DEBUG", "false").lower() == "true")
    host: str = field(default_factory=lambda: os.getenv("HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: int(os.getenv("PORT", "8000")))
    
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    
    @property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.environment == "production"
    
    @property
    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.environment == "development"


def get_config() -> Config:
    """Get the current configuration instance."""
    return Config()
