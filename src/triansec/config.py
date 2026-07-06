"""
Configuration management for TrianSec SDK.

This module provides configuration classes and utilities for the SDK.
Configuration can be loaded from:
- Environment variables (for SDK internal testing only)
- Dictionary
- Default values

IMPORTANT ARCHITECTURE NOTES:
    - The SDK is a THIN CLIENT - it doesn't make security decisions
    - The ENGINE URL is HARDCODED in the SDK - clients don't configure it
    - YOU (TrianSec) control where the security engine is hosted
    - Clients ONLY provide their API key and optional settings
    - API keys are provided by clients in request headers (X-API-Key)
    - SDK forwards API keys to YOUR security engine for validation

Environment Variables (for YOUR internal testing ONLY - NOT for clients):
    TRIANSEC_ENGINE_URL: Override engine URL (default: https://api.triansec.com)
    TRIANSEC_TIMEOUT: Request timeout in seconds (default: 5)
    TRIANSEC_RETRY_COUNT: Number of retry attempts (default: 3)
    TRIANSEC_FALLBACK_ACTION: Fallback action "allow" or "block" (default: "allow")
    TRIANSEC_CACHE_ENABLED: Enable local caching (default: true)
    TRIANSEC_CACHE_TTL: Cache TTL in seconds (default: 300)
    TRIANSEC_DEBUG: Enable debug mode (default: false)
    TRIANSEC_LOG_LEVEL: Log level (default: INFO)
    TRIANSEC_LOG_FORMAT: Log format "text" or "json" (default: "text")

Client Usage (Simplified):
    # Client ONLY provides API key
    app.add_middleware(
        SecurityMiddleware,
        api_key="ts_live_xxxxx"  # ← Only this!
    )
    
    # Optional settings
    app.add_middleware(
        SecurityMiddleware,
        api_key="ts_live_xxxxx",
        timeout=10,
        fallback_action="block",
        enable_cache=False
    )
    
    # Engine URL is automatically used - client doesn't configure it!
"""

import json
import os
import re
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Literal, Union
from urllib.parse import urlparse

from triansec.constants import (
    DEFAULT_ENGINE_URL,
    DEFAULT_TIMEOUT,
    DEFAULT_CACHE_TTL,
    DEFAULT_FALLBACK_ACTION,
    DEFAULT_RETRY_COUNT,
    DEFAULT_CACHE_MAXSIZE,
    ENV_TIMEOUT,
    ENV_RETRY_COUNT,
    ENV_FALLBACK_ACTION,
    ENV_CACHE_ENABLED,
    ENV_CACHE_TTL,
    ENV_DEBUG,
    ENV_LOG_LEVEL,
    ENV_LOG_FORMAT,
    CONTROL_PLANE_PREFIXES,
    LOG_LEVEL_INFO,
    API_KEY_PATTERN
)
from triansec.exceptions import ConfigurationError


# ============================================================
# 📋 CONFIGURATION DATACLASS
# ============================================================

@dataclass
class SecurityConfig:
    """
    Configuration for TrianSec SDK.
    
    IMPORTANT ARCHITECTURE NOTES:
        - The SDK is a THIN CLIENT - it doesn't make decisions
        - The ENGINE URL is HARDCODED in the SDK - clients don't configure it
        - YOU (TrianSec) control where the security engine is hosted
        - Clients ONLY provide their API key and optional settings
    
    Client Usage:
        # Client ONLY provides API key
        app.add_middleware(
            SecurityMiddleware,
            api_key="ts_live_xxxxx"
        )
        
        # Optional settings
        app.add_middleware(
            SecurityMiddleware,
            api_key="ts_live_xxxxx",
            timeout=10,
            fallback_action="block"
        )
    
    Attributes:
        api_key: Client's API key (required - provided by client)
        
        # Optional client settings
        timeout: Request timeout in seconds (default: 5)
        retry_count: Number of retry attempts (default: 3)
        fallback_action: Action when engine is unreachable (default: "allow")
                       - "allow": Fail open - let requests through (recommended)
                       - "block": Fail closed - block all requests
        enable_cache: Enable local decision caching (default: true)
        cache_ttl: Cache TTL in seconds (default: 300)
        cache_maxsize: Maximum cache size (number of entries) (default: 1000)
        enable_debug: Enable debug mode (default: false)
        log_level: Log level (default: INFO)
        log_format: Log format ("text" or "json") (default: "text")
        bypass_paths: List of path prefixes to bypass security
        extra: Additional configuration options (for future use)
    
    Note:
        engine_url is NOT in config - it's hardcoded in constants.py
        Clients should NEVER configure engine_url
    """
    
    # ============================================================
    # CLIENT PROVIDES THIS
    # ============================================================
    api_key: str
    
    # ============================================================
    # OPTIONAL CLIENT SETTINGS
    # ============================================================
    timeout: int = DEFAULT_TIMEOUT
    retry_count: int = DEFAULT_RETRY_COUNT
    
    # ⚠️ Default: "allow" (Fail Open - recommended for most use cases)
    fallback_action: Literal["allow", "block"] = DEFAULT_FALLBACK_ACTION
    
    enable_cache: bool = True
    cache_ttl: int = DEFAULT_CACHE_TTL
    cache_maxsize: int = DEFAULT_CACHE_MAXSIZE
    enable_debug: bool = False
    log_level: str = LOG_LEVEL_INFO
    log_format: Literal["text", "json"] = "text"
    bypass_paths: Optional[List[str]] = None
    extra: Dict[str, Any] = field(default_factory=dict)
    
    # ============================================================
    # ⚠️ NOT IN CONFIG - CLIENTS DON'T SET THIS!
    # engine_url is hardcoded in constants.py
    # ============================================================
    
    def __post_init__(self):
        """Validate configuration after initialization."""
        self._validate()
    
    def _validate(self) -> None:
        """
        Validate configuration values.
        
        Note: engine_url is NOT validated here because it's hardcoded.
        
        Raises:
            ConfigurationError: If any configuration is invalid
        """
        # Validate API key (client provides this)
        if not self.api_key:
            raise ConfigurationError(
                "API key is required. Please provide your TrianSec API key.",
                config_key="api_key"
            )
        
        # Validate timeout
        if self.timeout <= 0:
            raise ConfigurationError(
                f"Timeout must be positive: {self.timeout}",
                config_key="timeout",
                config_value=self.timeout
            )
        
        # Validate retry count
        if self.retry_count < 0:
            raise ConfigurationError(
                f"Retry count cannot be negative: {self.retry_count}",
                config_key="retry_count",
                config_value=self.retry_count
            )
        
        # Validate fallback action
        if self.fallback_action not in ("allow", "block"):
            raise ConfigurationError(
                f"Fallback action must be 'allow' or 'block': {self.fallback_action}",
                config_key="fallback_action",
                config_value=self.fallback_action
            )
        
        # Validate cache TTL
        if self.cache_ttl <= 0:
            raise ConfigurationError(
                f"Cache TTL must be positive: {self.cache_ttl}",
                config_key="cache_ttl",
                config_value=self.cache_ttl
            )
        
        # Validate cache maxsize
        if self.cache_maxsize <= 0:
            raise ConfigurationError(
                f"Cache maxsize must be positive: {self.cache_maxsize}",
                config_key="cache_maxsize",
                config_value=self.cache_maxsize
            )
        
        # Validate log format
        if self.log_format not in ("text", "json"):
            raise ConfigurationError(
                f"Log format must be 'text' or 'json': {self.log_format}",
                config_key="log_format",
                config_value=self.log_format
            )
    
    # ============================================================
    # 🔧 CONFIGURATION LOADERS
    # ============================================================
    
    @classmethod
    def from_env(cls) -> "SecurityConfig":
        """
        Load configuration from environment variables.
        
        NOTE: This is for YOUR (TrianSec) internal testing only!
        Clients should NOT use environment variables for configuration.
        
        Environment Variables:
            TRIANSEC_API_KEY: Client's API key (required)
            TRIANSEC_TIMEOUT: Request timeout (default: 5)
            TRIANSEC_RETRY_COUNT: Retry count (default: 3)
            TRIANSEC_FALLBACK_ACTION: Fallback action (default: "allow")
            TRIANSEC_CACHE_ENABLED: Enable cache (default: true)
            TRIANSEC_CACHE_TTL: Cache TTL (default: 300)
            TRIANSEC_DEBUG: Debug mode (default: false)
            TRIANSEC_LOG_LEVEL: Log level (default: INFO)
            TRIANSEC_LOG_FORMAT: Log format (default: "text")
        
        Note: TRIANSEC_ENGINE_URL is for internal testing only.
        Clients should NEVER set this.
        
        Returns:
            SecurityConfig instance
        
        Examples:
            >>> # For YOUR internal testing only
            >>> # export TRIANSEC_API_KEY="ts_live_xxxxx"
            >>> config = SecurityConfig.from_env()
            >>> config.api_key
            'ts_live_xxxxx'
        """
        return cls(
            api_key=os.getenv("TRIANSEC_API_KEY", ""),
            timeout=int(os.getenv(ENV_TIMEOUT, str(DEFAULT_TIMEOUT))),
            retry_count=int(os.getenv(ENV_RETRY_COUNT, str(DEFAULT_RETRY_COUNT))),
            fallback_action=os.getenv(ENV_FALLBACK_ACTION, DEFAULT_FALLBACK_ACTION),
            enable_cache=os.getenv(ENV_CACHE_ENABLED, "true").lower() == "true",
            cache_ttl=int(os.getenv(ENV_CACHE_TTL, str(DEFAULT_CACHE_TTL))),
            enable_debug=os.getenv(ENV_DEBUG, "false").lower() == "true",
            log_level=os.getenv(ENV_LOG_LEVEL, LOG_LEVEL_INFO),
            log_format=os.getenv(ENV_LOG_FORMAT, "text"),  # type: ignore
            bypass_paths=None,
        )
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityConfig":
        """
        Load configuration from dictionary.
        
        Args:
            data: Dictionary with configuration values
        
        Returns:
            SecurityConfig instance
        
        Examples:
            >>> config = SecurityConfig.from_dict({
            ...     "api_key": "ts_live_xxxxx",
            ...     "timeout": 10,
            ...     "fallback_action": "block"
            ... })
            >>> config.timeout
            10
        """
        # Filter out None values
        filtered = {k: v for k, v in data.items() if v is not None}
        
        # Ignore engine_url if present (clients shouldn't set this)
        filtered.pop("engine_url", None)
        
        return cls(**filtered)
    
    @classmethod
    def from_json(cls, json_str: str) -> "SecurityConfig":
        """
        Load configuration from JSON string.
        
        Args:
            json_str: JSON string with configuration values
        
        Returns:
            SecurityConfig instance
        
        Examples:
            >>> config = SecurityConfig.from_json(
            ...     '{"api_key": "ts_live_xxxxx", "timeout": 10}'
            ... )
            >>> config.timeout
            10
        """
        try:
            data = json.loads(json_str)
            return cls.from_dict(data)
        except json.JSONDecodeError as e:
            raise ConfigurationError(
                f"Invalid JSON configuration: {e}",
                config_key="json",
                config_value=json_str[:100]
            )
    
    # ============================================================
    # 🏠 ENGINE URL (Hardcoded - Clients Don't Configure This!)
    # ============================================================
    
    @staticmethod
    def get_engine_url() -> str:
        """
        Get the security engine URL.
        
        The engine URL is HARDCODED in the SDK.
        Clients should NEVER configure this.
        
        Returns:
            Security engine URL
        
        Examples:
            >>> # Client code - automatically uses your hardcoded URL
            >>> url = SecurityConfig.get_engine_url()
            >>> url
            'https://api.triansec.com'
        """
        return DEFAULT_ENGINE_URL
    
    # ============================================================
    # 🔄 CONFIGURATION HELPERS
    # ============================================================
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert configuration to dictionary.
        
        Returns:
            Dictionary representation of configuration
        
        Examples:
            >>> config = SecurityConfig(api_key="ts_live_xxxxx")
            >>> config.to_dict()["api_key"]
            'ts_live_xxxxx'
        """
        return {
            "api_key": self.api_key,
            "timeout": self.timeout,
            "retry_count": self.retry_count,
            "fallback_action": self.fallback_action,
            "enable_cache": self.enable_cache,
            "cache_ttl": self.cache_ttl,
            "cache_maxsize": self.cache_maxsize,
            "enable_debug": self.enable_debug,
            "log_level": self.log_level,
            "log_format": self.log_format,
            "bypass_paths": self.bypass_paths,
            "extra": self.extra,
        }
    
    def to_env_dict(self) -> Dict[str, str]:
        """
        Convert configuration to environment variable dictionary.
        
        Note: This is for YOUR (TrianSec) internal testing only.
        
        Returns:
            Dictionary of environment variables
        
        Examples:
            >>> config = SecurityConfig(api_key="ts_live_xxxxx")
            >>> env = config.to_env_dict()
            >>> env["TRIANSEC_API_KEY"]
            'ts_live_xxxxx'
        """
        return {
            "TRIANSEC_API_KEY": self.api_key,
            ENV_TIMEOUT: str(self.timeout),
            ENV_RETRY_COUNT: str(self.retry_count),
            ENV_FALLBACK_ACTION: self.fallback_action,
            ENV_CACHE_ENABLED: str(self.enable_cache).lower(),
            ENV_CACHE_TTL: str(self.cache_ttl),
            ENV_DEBUG: str(self.enable_debug).lower(),
            ENV_LOG_LEVEL: self.log_level,
            ENV_LOG_FORMAT: self.log_format,
        }
    
    def get_bypass_paths(self) -> List[str]:
        """
        Get bypass paths (with default if not set).
        
        Returns:
            List of bypass path prefixes
        
        Examples:
            >>> config = SecurityConfig(api_key="ts_live_xxxxx")
            >>> config.get_bypass_paths()
            ['/api/auth', '/api/client', ...]
        """
        if self.bypass_paths is not None:
            return self.bypass_paths
        return CONTROL_PLANE_PREFIXES
    
    def get_masked_api_key(self) -> str:
        """
        Get masked API key for logging.
        
        Returns:
            Masked API key
        
        Examples:
            >>> config = SecurityConfig(api_key="ts_live_1234567890abcdef")
            >>> config.get_masked_api_key()
            'ts_live_****...def'
        """
        if not self.api_key:
            return ""
        
        if len(self.api_key) <= 16:
            return "****"
        
        prefix = self.api_key[:8]
        suffix = self.api_key[-4:]
        return f"{prefix}****...{suffix}"
    
    def is_configured(self) -> bool:
        """
        Check if configuration is fully configured.
        
        Returns:
            True if API key is set
        
        Examples:
            >>> config = SecurityConfig(api_key="ts_live_xxxxx")
            >>> config.is_configured()
            True
        """
        return bool(self.api_key)
    
    # ============================================================
    # 🔄 MERGE CONFIGURATION
    # ============================================================
    
    def merge(self, override: Dict[str, Any]) -> "SecurityConfig":
        """
        Merge with override dictionary.
        
        Args:
            override: Dictionary with values to override
        
        Returns:
            New SecurityConfig instance with merged values
        
        Examples:
            >>> base = SecurityConfig(api_key="ts_live_xxxxx", timeout=5)
            >>> merged = base.merge({"timeout": 10, "enable_debug": True})
            >>> merged.timeout
            10
            >>> merged.api_key
            'ts_live_xxxxx'
        """
        data = self.to_dict()
        # Ignore engine_url if present (clients shouldn't set this)
        overrides = {k: v for k, v in override.items() if v is not None and k != "engine_url"}
        data.update(overrides)
        return SecurityConfig.from_dict(data)
    
    def merge_with_env(self) -> "SecurityConfig":
        """
        Merge current configuration with environment variables.
        
        NOTE: For YOUR (TrianSec) internal testing only.
        
        Environment variables take precedence.
        
        Returns:
            New SecurityConfig instance with environment values merged
        
        Examples:
            >>> config = SecurityConfig(api_key="ts_live_xxxxx", timeout=5)
            # If TRIANSEC_TIMEOUT=10 is set in environment
            >>> merged = config.merge_with_env()
            >>> merged.timeout
            10
        """
        env_config = SecurityConfig.from_env()
        return self.merge(env_config.to_dict())
    
    # ============================================================
    # 📋 VALIDATION HELPERS
    # ============================================================
    
    def get_validation_errors(self) -> List[str]:
        """
        Get all validation errors.
        
        Returns:
            List of validation error messages
        
        Examples:
            >>> config = SecurityConfig(api_key="")
            >>> config.get_validation_errors()
            ['API key is required']
        """
        errors = []
        
        if not self.api_key:
            errors.append("API key is required")
        elif not self._validate_api_key_format():
            errors.append(
                f"Invalid API key format: {self.get_masked_api_key()}. "
                "Expected format: ts_{live|test|dev}_{48 hex characters}"
            )
        
        if self.timeout <= 0:
            errors.append(f"Timeout must be positive: {self.timeout}")
        
        if self.retry_count < 0:
            errors.append(f"Retry count cannot be negative: {self.retry_count}")
        
        if self.fallback_action not in ("allow", "block"):
            errors.append(
                f"Fallback action must be 'allow' or 'block': {self.fallback_action}"
            )
        
        if self.cache_ttl <= 0:
            errors.append(f"Cache TTL must be positive: {self.cache_ttl}")
        
        if self.cache_maxsize <= 0:
            errors.append(f"Cache maxsize must be positive: {self.cache_maxsize}")
        
        if self.log_format not in ("text", "json"):
            errors.append(f"Log format must be 'text' or 'json': {self.log_format}")
        
        return errors
    
    def _validate_api_key_format(self) -> bool:
        """
        Validate API key format.
        
        Expected format: ts_{live|test|dev}_{48 hex characters}
        
        Returns:
            True if API key format is valid
        """
        return bool(re.match(API_KEY_PATTERN, self.api_key))
    
    def raise_if_invalid(self) -> None:
        """
        Raise ConfigurationError if configuration is invalid.
        
        Raises:
            ConfigurationError: If any configuration is invalid
        
        Examples:
            >>> config = SecurityConfig(api_key="")
            >>> config.raise_if_invalid()
            Traceback (most recent call last):
            ...
            ConfigurationError: Invalid configuration: API key is required
        """
        errors = self.get_validation_errors()
        if errors:
            raise ConfigurationError(
                f"Invalid configuration:\n  - " + "\n  - ".join(errors)
            )
    
    def __repr__(self) -> str:
        """String representation of configuration."""
        return (
            f"SecurityConfig("
            f"api_key={self.get_masked_api_key()}, "
            f"engine_url={self.get_engine_url()}, "
            f"timeout={self.timeout}, "
            f"fallback_action={self.fallback_action}, "
            f"cache_enabled={self.enable_cache}, "
            f"debug={self.enable_debug}"
            f")"
        )


# ============================================================
# 🔧 CONFIGURATION HELPER FUNCTIONS
# ============================================================

def create_config(
    api_key: str,
    timeout: Optional[int] = None,
    retry_count: Optional[int] = None,
    fallback_action: Optional[Literal["allow", "block"]] = None,
    enable_cache: Optional[bool] = None,
    cache_ttl: Optional[int] = None,
    cache_maxsize: Optional[int] = None,
    enable_debug: Optional[bool] = None,
    log_level: Optional[str] = None,
    log_format: Optional[Literal["text", "json"]] = None,
    bypass_paths: Optional[List[str]] = None,
    **kwargs,
) -> SecurityConfig:
    """
    Create a configuration instance.
    
    Client provides API key and optional settings.
    Engine URL is automatically used (hardcoded in SDK).
    
    Args:
        api_key: Client's API key (required)
        timeout: Request timeout
        retry_count: Retry count
        fallback_action: Fallback action (default: "allow")
        enable_cache: Enable cache
        cache_ttl: Cache TTL
        cache_maxsize: Cache maxsize
        enable_debug: Debug mode
        log_level: Log level
        log_format: Log format
        bypass_paths: Bypass paths
        **kwargs: Additional configuration options (stored in extra)
    
    Returns:
        SecurityConfig instance
    
    Examples:
        >>> # Client ONLY provides API key
        >>> config = create_config(api_key="ts_live_xxxxx")
        
        >>> # With optional settings
        >>> config = create_config(
        ...     api_key="ts_live_xxxxx",
        ...     timeout=10,
        ...     fallback_action="block"
        ... )
        >>> config.engine_url  # Automatically uses hardcoded URL
        'https://api.triansec.com'
    """
    # Start with default
    config_dict = {
        "api_key": api_key,
        "timeout": timeout or DEFAULT_TIMEOUT,
        "retry_count": retry_count or DEFAULT_RETRY_COUNT,
        "fallback_action": fallback_action or DEFAULT_FALLBACK_ACTION,
        "enable_cache": enable_cache if enable_cache is not None else True,
        "cache_ttl": cache_ttl or DEFAULT_CACHE_TTL,
        "cache_maxsize": cache_maxsize or DEFAULT_CACHE_MAXSIZE,
        "enable_debug": enable_debug or False,
        "log_level": log_level or LOG_LEVEL_INFO,
        "log_format": log_format or "text",
        "bypass_paths": bypass_paths,
    }
    
    # Extra kwargs (ignore engine_url if present)
    if kwargs:
        kwargs.pop("engine_url", None)
        config_dict["extra"] = kwargs
    
    return SecurityConfig(**config_dict)


def load_config(
    source: Optional[Union[str, Dict[str, Any], SecurityConfig]] = None,
    **kwargs,
) -> SecurityConfig:
    """
    Load configuration from various sources.
    
    Args:
        source: Configuration source (JSON string, dict, or SecurityConfig)
        **kwargs: Additional configuration parameters
    
    Returns:
        SecurityConfig instance
    
    Examples:
        >>> # From dict
        >>> config = load_config({"api_key": "ts_live_xxxxx"})
        
        >>> # From JSON string
        >>> config = load_config('{"api_key": "ts_live_xxxxx"}')
        
        >>> # With additional params
        >>> config = load_config(
        ...     {"api_key": "ts_live_xxxxx"},
        ...     timeout=10,
        ...     enable_debug=True
        ... )
    """
    if source is None:
        # Just use kwargs
        return create_config(**kwargs)
    
    if isinstance(source, SecurityConfig):
        # Already a config
        return source.merge(kwargs)
    
    if isinstance(source, dict):
        # Dictionary source
        return create_config(**{**source, **kwargs})
    
    if isinstance(source, str):
        # JSON string source
        try:
            data = json.loads(source)
            return create_config(**{**data, **kwargs})
        except json.JSONDecodeError as e:
            raise ConfigurationError(
                f"Invalid JSON configuration: {e}",
                config_key="source",
                config_value=source[:100]
            )
    
    raise ConfigurationError(
        f"Invalid configuration source type: {type(source)}",
        config_key="source",
        config_value=str(source)[:100]
    )


# ============================================================
# 📋 EXPORTS
# ============================================================

__all__ = [
    "SecurityConfig",
    "create_config",
    "load_config",
]