"""
TrianSec Security Module.

This module provides the main entry point for TrianSec SDK integration.
It offers a clean, unified interface for adding security to your applications.

Usage:
    from fastapi import FastAPI
    from triansec.security import TriAnSec

    app = FastAPI()
    
    # Initialize security (default: fail open)
    security = TriAnSec(
        api_key="ts_live_xxxxx",
        timeout=10,
    )
    
    # Add to your app
    security.install(app)
"""

from typing import Optional, List, Literal, Dict, Any

from fastapi import FastAPI, Request

from triansec.config import SecurityConfig, create_config
from triansec.constants import (
    DEFAULT_TIMEOUT,
    DEFAULT_FALLBACK_ACTION,
    DEFAULT_RETRY_COUNT,
    DEFAULT_CACHE_TTL,
    DEFAULT_CACHE_MAXSIZE,
)
from triansec.logger import get_logger
from triansec.exceptions import ConfigurationError
from triansec.middleware import TriAnSec as TriAnSecMiddleware

logger = get_logger(__name__)


class TriAnSec:
    """
    Main entry point for TrianSec security integration.
    
    This class provides a clean interface for adding security to your
    FastAPI applications. It handles configuration, middleware installation,
    and lifecycle management.
    
    Attributes:
        config: Security configuration
        middleware: Security middleware instance (after installation)
    
    Usage:
        >>> from fastapi import FastAPI
        >>> from triansec.security import TriAnSec
        >>> 
        >>> app = FastAPI()
        >>> 
        >>> # Initialize with default settings (fail open)
        >>> security = TriAnSec(api_key="ts_live_xxxxx")
        >>> security.install(app)
        >>> 
        >>> # Or with custom settings
        >>> security = TriAnSec(
        ...     api_key="ts_live_xxxxx",
        ...     timeout=10,
        ...     fallback_action="block",  # Only for high-security needs
        ...     enable_cache=True,
        ...     cache_ttl=600,
        ... )
        >>> security.install(app)
    """
    
    def __init__(
        self,
        api_key: str,
        engine_url: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
        retry_count: int = DEFAULT_RETRY_COUNT,
        fallback_action: Literal["allow", "block"] = DEFAULT_FALLBACK_ACTION,
        enable_cache: bool = True,
        cache_ttl: int = DEFAULT_CACHE_TTL,
        cache_maxsize: int = DEFAULT_CACHE_MAXSIZE,
        enable_debug: bool = False,
        bypass_paths: Optional[List[str]] = None,
        config: Optional[SecurityConfig] = None,
        **kwargs,
    ):
        """
        Initialize TrianSec security.
        
        Args:
            api_key: TrianSec API key (required)
            engine_url: Security engine URL (defaults to hardcoded URL)
            timeout: Request timeout in seconds (default: 5)
            retry_count: Number of retry attempts (default: 3)
            fallback_action: Action when engine is unreachable
                           - "allow": Fail open - let requests through (RECOMMENDED)
                           - "block": Fail closed - block all requests (high-security only)
                           Default: "allow"
            enable_cache: Enable local decision caching (default: True)
            cache_ttl: Cache TTL in seconds (default: 300)
            cache_maxsize: Maximum cache entries (default: 1000)
            enable_debug: Enable debug mode (default: False)
            bypass_paths: Paths to bypass security
            config: SecurityConfig instance (overrides individual parameters)
            **kwargs: Additional configuration options
        
        Raises:
            ConfigurationError: If API key is not provided
        
        Examples:
            >>> # Basic setup (fail open - recommended)
            >>> security = TriAnSec(api_key="ts_live_xxxxx")
            >>> 
            >>> # With custom settings
            >>> security = TriAnSec(
            ...     api_key="ts_live_xxxxx",
            ...     timeout=10,
            ...     fallback_action="block",  # Only if you need fail-closed
            ...     enable_debug=True,
            ... )
        """
        if config is None:
            self.config = create_config(
                api_key=api_key,
                engine_url=engine_url,
                timeout=timeout,
                retry_count=retry_count,
                fallback_action=fallback_action,
                enable_cache=enable_cache,
                cache_ttl=cache_ttl,
                cache_maxsize=cache_maxsize,
                enable_debug=enable_debug,
                bypass_paths=bypass_paths,
                **kwargs,
            )
        else:
            self.config = config
            
            # Override with explicit parameters if provided
            if api_key:
                self.config.api_key = api_key
            if engine_url:
                self.config.engine_url = engine_url
            if timeout:
                self.config.timeout = timeout
            if retry_count:
                self.config.retry_count = retry_count
            if fallback_action:
                self.config.fallback_action = fallback_action
            if enable_cache is not None:
                self.config.enable_cache = enable_cache
            if cache_ttl:
                self.config.cache_ttl = cache_ttl
            if cache_maxsize:
                self.config.cache_maxsize = cache_maxsize
            if enable_debug is not None:
                self.config.enable_debug = enable_debug
            if bypass_paths:
                self.config.bypass_paths = bypass_paths
        
        self.config.raise_if_invalid()
        self._middleware = None
        self._installed = False
        
        logger.info(
            f"TriAnSec initialized: "
            f"engine_url={self.config.get_engine_url_masked()}, "
            f"fallback_action={self.config.fallback_action} (fail {'open' if self.config.fallback_action == 'allow' else 'closed'}), "
            f"cache_enabled={self.config.enable_cache}"
        )
    
    # ============================================================
    # 🔧 INSTALLATION
    # ============================================================
    
    def install(self, app: FastAPI) -> "TriAnSec":
        """
        Install security middleware into FastAPI application.
        
        Args:
            app: FastAPI application instance
        
        Returns:
            self: For method chaining
        
        Examples:
            >>> app = FastAPI()
            >>> security = TriAnSec(api_key="ts_live_xxxxx")
            >>> security.install(app)
        """
        if self._installed:
            logger.warning("Security middleware already installed")
            return self
        
        # Add the middleware using TriAnSecMiddleware class
        app.add_middleware(
            TriAnSecMiddleware,
            config=self.config,
        )
        
        self._installed = True
        
        logger.info(
            f"TriAnSec installed: "
            f"engine_url={self.config.get_engine_url_masked()}, "
            f"fallback_action={self.config.fallback_action} (fail {'open' if self.config.fallback_action == 'allow' else 'closed'})"
        )
        
        return self
    
    # ============================================================
    # 🔧 HEALTH CHECK
    # ============================================================
    
    def add_health_endpoint(
        self,
        app: FastAPI,
        path: str = "/health/security",
    ) -> "TriAnSec":
        """
        Add a health check endpoint.
        
        Args:
            app: FastAPI application instance
            path: Health check endpoint path
        
        Returns:
            self: For method chaining
        
        Examples:
            >>> app = FastAPI()
            >>> security = TriAnSec(api_key="ts_live_xxxxx")
            >>> security.install(app)
            >>> security.add_health_endpoint(app)
        """
        @app.get(path, tags=["Security"])
        async def security_health(request: Request) -> Dict[str, Any]:
            """Health check for TrianSec security."""
            return {
                "status": "healthy",
                "message": "TrianSec security is active",
                "engine_url": self.config.get_engine_url_masked(),
                "fallback_action": self.config.fallback_action,
                "fail_mode": "open" if self.config.fallback_action == "allow" else "closed",
                "cache_enabled": self.config.enable_cache,
                "installed": self._installed,
            }
        
        logger.info(f"Health endpoint added at: {path}")
        return self
    
    # ============================================================
    # 🔧 SHUTDOWN
    # ============================================================
    
    def add_shutdown_handler(self, app: FastAPI) -> "TriAnSec":
        """
        Add shutdown handler for cleanup.
        
        Args:
            app: FastAPI application instance
        
        Returns:
            self: For method chaining
        
        Examples:
            >>> app = FastAPI()
            >>> security = TriAnSec(api_key="ts_live_xxxxx")
            >>> security.install(app)
            >>> security.add_shutdown_handler(app)
        """
        @app.on_event("shutdown")
        async def _shutdown_handler():
            await self.close()
        
        logger.info("Shutdown handler added")
        return self
    
    async def close(self) -> None:
        """Close security resources."""
        if self._middleware:
            await self._middleware.close()
        
        logger.info("TriAnSec closed")
    
    # ============================================================
    # 📋 PROPERTIES
    # ============================================================
    
    @property
    def is_installed(self) -> bool:
        """Check if security is installed."""
        return self._installed
    
    @property
    def api_key(self) -> str:
        """Get API key (masked)."""
        return self.config.get_masked_api_key()
    
    @property
    def engine_url(self) -> str:
        """Get engine URL."""
        return self.config.get_engine_url_masked()
    
    @property
    def fail_mode(self) -> str:
        """Get fail mode: 'open' or 'closed'."""
        return "open" if self.config.fallback_action == "allow" else "closed"
    
    def get_config(self) -> SecurityConfig:
        """Get full configuration."""
        return self.config
    
    # ============================================================
    # 📊 STATS
    # ============================================================
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get security statistics.
        
        Returns:
            Dictionary with security stats
        
        Examples:
            >>> stats = security.get_stats()
            >>> stats["installed"]
            True
        """
        return {
            "installed": self._installed,
            "engine_url": self.config.get_engine_url_masked(),
            "timeout": self.config.timeout,
            "retry_count": self.config.retry_count,
            "fallback_action": self.config.fallback_action,
            "fail_mode": "open" if self.config.fallback_action == "allow" else "closed",
            "cache_enabled": self.config.enable_cache,
            "cache_ttl": self.config.cache_ttl,
            "debug_enabled": self.config.enable_debug,
        }
    
    def __repr__(self) -> str:
        """String representation."""
        return (
            f"TriAnSec("
            f"installed={self._installed}, "
            f"engine_url={self.config.get_engine_url_masked()}, "
            f"fallback_action={self.config.fallback_action} (fail {'open' if self.config.fallback_action == 'allow' else 'closed'})"
            f")"
        )


# ============================================================
# 🔧 CONVENIENCE FUNCTION
# ============================================================

def setup_security(
    app: FastAPI,
    api_key: str,
    engine_url: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
    retry_count: int = DEFAULT_RETRY_COUNT,
    fallback_action: Literal["allow", "block"] = DEFAULT_FALLBACK_ACTION,
    enable_cache: bool = True,
    cache_ttl: int = DEFAULT_CACHE_TTL,
    cache_maxsize: int = DEFAULT_CACHE_MAXSIZE,
    enable_debug: bool = False,
    bypass_paths: Optional[List[str]] = None,
    add_health: bool = True,
    health_path: str = "/health/security",
    add_shutdown: bool = True,
    **kwargs,
) -> TriAnSec:
    """
    One-line setup for TrianSec security.
    
    This is a convenience function that creates a TriAnSec instance,
    installs it, and optionally adds health endpoint and shutdown handler.
    
    Args:
        app: FastAPI application instance
        api_key: TrianSec API key (required)
        engine_url: Security engine URL
        timeout: Request timeout in seconds (default: 5)
        retry_count: Number of retry attempts (default: 3)
        fallback_action: Fallback action (default: "allow")
                       - "allow": Fail open (RECOMMENDED)
                       - "block": Fail closed (high-security only)
        enable_cache: Enable local caching (default: True)
        cache_ttl: Cache TTL in seconds (default: 300)
        cache_maxsize: Maximum cache entries (default: 1000)
        enable_debug: Enable debug mode (default: False)
        bypass_paths: Paths to bypass security
        add_health: Add health endpoint (default: True)
        health_path: Health endpoint path (default: "/health/security")
        add_shutdown: Add shutdown handler (default: True)
        **kwargs: Additional configuration options
    
    Returns:
        TriAnSec: The security instance
    
    Examples:
        >>> from fastapi import FastAPI
        >>> from triansec.security import setup_security
        >>> 
        >>> app = FastAPI()
        >>> 
        >>> # Default setup (fail open - recommended)
        >>> security = setup_security(
        ...     app,
        ...     api_key="ts_live_xxxxx",
        ...     timeout=10,
        ... )
        >>> 
        >>> # High-security setup (fail closed)
        >>> security = setup_security(
        ...     app,
        ...     api_key="ts_live_xxxxx",
        ...     timeout=10,
        ...     fallback_action="block",  # Only if you need fail-closed
        ... )
    """
    security = TriAnSec(
        api_key=api_key,
        engine_url=engine_url,
        timeout=timeout,
        retry_count=retry_count,
        fallback_action=fallback_action,
        enable_cache=enable_cache,
        cache_ttl=cache_ttl,
        cache_maxsize=cache_maxsize,
        enable_debug=enable_debug,
        bypass_paths=bypass_paths,
        **kwargs,
    )
    
    security.install(app)
    
    if add_health:
        security.add_health_endpoint(app, path=health_path)
    
    if add_shutdown:
        security.add_shutdown_handler(app)
    
    logger.info(
        f"TrianSec security setup complete: "
        f"fail_mode={'open' if fallback_action == 'allow' else 'closed'}"
    )
    
    return security


# ============================================================
# 📋 EXPORTS
# ============================================================

__all__ = [
    "TriAnSec",
    "setup_security",
]