"""
TrianSec API Security SDK.

A lightweight Python SDK for integrating TrianSec API Security Platform
into your applications. Provides middleware for FastAPI/Starlette that
intercepts requests, sends them to the TrianSec security engine for
behavioral analysis, and applies security decisions (ALLOW, BLOCK, THROTTLE).

Example:
    from fastapi import FastAPI
    from triansec import TriAnSec

    app = FastAPI()

    app.add_middleware(
        TriAnSec,
        api_key="ts_live_xxxxxxxxx",
    )

    @app.get("/")
    async def root():
        return {"message": "Protected by TrianSec"}

Version: 0.1.3
"""

__version__: str = "0.1.3"
__title__: str = "triansec"
__description__:str = "TrianSec API Security SDK"
__author__: str = "Aniket Paswan"

from triansec.constants import DEFAULT_ENGINE_URL, SDK_VERSION
from triansec.config import SecurityConfig, create_config, load_config
from triansec.middleware import TriAnSec
from triansec.client import SecurityClient, create_client
from triansec.cache import (
    SecurityCache,
    get_global_cache,
    set_global_cache,
    disable_global_cache,
    enable_global_cache,
    clear_global_cache,
)
from triansec.exceptions import (
    SecurityError,
    ConfigurationError,
    AuthenticationError,
    SecurityEngineError,
    SecurityEngineTimeoutError,
    SecurityEngineUnavailableError,
    SecurityEngineInvalidResponseError,
    RateLimitError,
    CacheError,
    ValidationError,
    SDKError,
)
from triansec.logger import (
    configure_logging,
    setup_default_logging,
    get_logger,
)
from triansec.models.response import (
    RequestData,
    SecurityDecision,
)
from triansec.security import setup_security
from triansec.utils import (
    validate_block_duration,
    is_valid_block_duration,
    get_block_duration_hours,
    get_block_duration_seconds,
    get_block_duration_description,
    generate_fingerprint,
    generate_behavioral_fingerprint,
    extract_ip_from_headers,
    is_private_ip,
    is_valid_ip,
    mask_ip,
    validate_api_key,
    mask_api_key,
    get_api_key_environment,
    safe_json_parse,
    truncate_body,
    redact_sensitive_headers,
    format_timestamp_iso,
    parse_timestamp_iso,
    truncate_string,
    safe_get,
    is_retryable_status_code,
    is_retryable_exception,
    calculate_backoff,
    normalize_url,
    join_url,
    merge_dicts,
    filter_none_values,
    is_valid_uuid,
    is_valid_hex,
    sanitize_input,
)

__all__: list[str] = [
    # Version
    "__version__",
    "__title__",
    "__description__",
    "__author__",
    
    # Version constants
    "DEFAULT_ENGINE_URL",
    "SDK_VERSION",
    
    # Main middleware
    "TriAnSec",
    
    # Setup function
    "setup_security",
    
    # Configuration
    "SecurityConfig",
    "create_config",
    "load_config",
    
    # Client
    "SecurityClient",
    "create_client",
    
    # Cache
    "SecurityCache",
    "get_global_cache",
    "set_global_cache",
    "disable_global_cache",
    "enable_global_cache",
    "clear_global_cache",
    
    # Exceptions
    "SecurityError",
    "ConfigurationError",
    "AuthenticationError",
    "SecurityEngineError",
    "SecurityEngineTimeoutError",
    "SecurityEngineUnavailableError",
    "SecurityEngineInvalidResponseError",
    "RateLimitError",
    "CacheError",
    "ValidationError",
    "SDKError",
    
    # Logging
    "configure_logging",
    "setup_default_logging",
    "get_logger",
    
    # Models
    "RequestData",
    "SecurityDecision",
    
    # Utils - Block Duration
    "validate_block_duration",
    "is_valid_block_duration",
    "get_block_duration_hours",
    "get_block_duration_seconds",
    "get_block_duration_description",
    
    # Utils - Fingerprint
    "generate_fingerprint",
    "generate_behavioral_fingerprint",
    
    # Utils - IP
    "extract_ip_from_headers",
    "is_private_ip",
    "is_valid_ip",
    "mask_ip",
    
    # Utils - API Key
    "validate_api_key",
    "mask_api_key",
    "get_api_key_environment",
    
    # Utils - Request
    "safe_json_parse",
    "truncate_body",
    "redact_sensitive_headers",
    
    # Utils - Timestamp
    "format_timestamp_iso",
    "parse_timestamp_iso",
    
    # Utils - String
    "truncate_string",
    "safe_get",
    
    # Utils - Retry
    "is_retryable_status_code",
    "is_retryable_exception",
    "calculate_backoff",
    
    # Utils - URL
    "normalize_url",
    "join_url",
    
    # Utils - Dict
    "merge_dicts",
    "filter_none_values",
    
    # Utils - Validation
    "is_valid_uuid",
    "is_valid_hex",
    "sanitize_input",
]


# ============================================================
# 🔧 DEFAULT LOGGING SETUP
# ============================================================

# Set up default logging when the SDK is imported
try:
    setup_default_logging()
except Exception:
    # Silently fail if logging setup fails
    # The user can still configure logging manually
    pass


# ============================================================
# 📋 PACKAGE METADATA
# ============================================================

def get_version() -> str:
    """
    Get the SDK version.
    
    Returns:
        SDK version string
    
    Examples:
        >>> from triansec import get_version
        >>> get_version()
        '0.1.0'
    """
    return __version__


def get_info() -> dict[str, str]:
    """
    Get package information.
    
    Returns:
        Dictionary with package information
    
    Examples:
        >>> from triansec import get_info
        >>> info = get_info()
        >>> info["name"]
        'triansec'
    """
    return {
        "name": __title__,
        "version": __version__,
        "description": __description__,
        "author": __author__,
    }


# ============================================================
# 🔄 CLEANUP
# ============================================================

async def close() -> None:
    """
    Clean up SDK resources.
    
    Closes the global HTTP client and cache if they exist.
    Should be called when the application is shutting down.
    
    Examples:
        >>> # In FastAPI shutdown event
        >>> @app.on_event("shutdown")
        ... async def shutdown():
        ...     await triansec.close()
    """
    try:
        cache = get_global_cache()
    except Exception:
        pass
    
    logger = get_logger(__name__)
    logger.info("TrianSec SDK closed")