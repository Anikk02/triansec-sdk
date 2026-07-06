"""
Custom exceptions for TrianSec SDK.

This module defines all exceptions that can be raised by the SDK.
They are organized hierarchically to allow fine-grained error handling.

Exception Hierarchy:
    SecurityError (Base)
    ├── ConfigurationError
    │   └── DEVELOPER problem: Missing config, wrong env vars
    ├── AuthenticationError
    │   └── CLIENT problem: Invalid/expired API key (NEVER expose to users!)
    ├── SecurityEngineError
    │   ├── SecurityEngineTimeoutError
    │   ├── SecurityEngineUnavailableError
    │   └── SecurityEngineInvalidResponseError
    ├── RateLimitError
    │   └── CLIENT/APP problem: Too many requests (retry with backoff)
    ├── CacheError
    ├── ValidationError
    │   └── DEVELOPER problem: Invalid request data
    └── SDKError
        └── TRIANSEC problem: Internal SDK error

ERROR OWNERSHIP:
    - ConfigurationError: Developer forgot to configure
    - AuthenticationError: Client's API key is invalid (NOT developer's fault!)
    - RateLimitError: Client/App hitting limits
    - SecurityEngineError: TrianSec service issue
    - ValidationError: Developer sent invalid data
    - SDKError: TrianSec SDK bug

IMPORTANT: AuthenticationError should NEVER be exposed to end users!
    - End users don't know about API keys
    - Return generic error like "Service temporarily unavailable"
    - Log CRITICAL with CLIENT API KEY context
    - Operations team should investigate
"""

from typing import Optional, Dict, Any, List


# ============================================================
# 🏛️ BASE EXCEPTION
# ============================================================

class SecurityError(Exception):
    """
    Base exception for all TrianSec SDK errors.
    
    All custom exceptions inherit from this class.
    
    Attributes:
        message: Error message
        details: Additional error details (optional)
        request_uuid: Request UUID (optional)
        original_exception: Original exception (optional)
    """
    
    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        request_uuid: Optional[str] = None,
        original_exception: Optional[Exception] = None,
    ):
        self.message = message
        self.details = details or {}
        self.request_uuid = request_uuid
        self.original_exception = original_exception
        super().__init__(message)
    
    def __str__(self) -> str:
        """String representation of the exception."""
        base = self.message
        if self.request_uuid:
            base = f"{base} [request_uuid={self.request_uuid}]"
        if self.details:
            base = f"{base} - {self.details}"
        return base
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert exception to dictionary for logging/API responses.
        
        Returns:
            Dictionary representation of the exception
        """
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            "details": self.details,
            "request_uuid": self.request_uuid,
        }


# ============================================================
# ⚙️ CONFIGURATION ERRORS (Developer Problem)
# ============================================================

class ConfigurationError(SecurityError):
    """
    Raised when SDK configuration is invalid.
    
    OWNER: Developer
    - Developer forgot to set environment variables
    - Developer passed wrong parameters
    - Developer misconfigured the SDK
    
    Developer Fix:
        - Set TRIANSEC_API_KEY environment variable
        - Set TRIANSEC_ENGINE_URL environment variable
        - Pass valid config to middleware
        - Check integration code
    
    This should crash the application on startup with clear instructions.
    """
    
    def __init__(
        self,
        message: str,
        config_key: Optional[str] = None,
        config_value: Optional[Any] = None,
        **kwargs,
    ):
        details = kwargs.pop("details", {})
        if config_key:
            details["config_key"] = config_key
        if config_value is not None:
            details["config_value"] = str(config_value)
        super().__init__(message, details=details, **kwargs)


# ============================================================
# 🔐 AUTHENTICATION ERRORS (Client Problem - NEVER Expose to Users!)
# ============================================================

class AuthenticationError(SecurityError):
    """
    Raised when API key authentication fails.
    
    OWNER: Client (Organization using TrianSec)
    - Client's API key is invalid
    - Client's API key has expired
    - Client's API key was revoked
    - Client's API key has wrong permissions
    - Client's subscription expired
    
    NOT the developer's fault - they just configured what client provided!
    NOT the end user's fault - they don't know about API keys!
    
    Developer Action:
        1. Log CRITICAL with "CLIENT API KEY" context
        2. Notify client (operations team) to check their key
        3. NEVER expose to end users
        4. Use fallback action (allow or block)
        5. Return generic "Service unavailable" to users
    
    Client Action:
        - Login to TrianSec dashboard
        - Check API key status and permissions
        - Regenerate API key if needed
        - Provide new key to developer
    
    When this occurs at RUNTIME (after startup validation):
        - This means client's key was valid but is now invalid
        - Key may have been revoked by admin
        - Key may have expired
        - Subscription may have lapsed
    
    END USERS SHOULD NEVER SEE THIS ERROR!
    """
    
    def __init__(
        self,
        message: str = "API key authentication failed. Please check your TrianSec API key.",
        api_key_masked: Optional[str] = None,
        status_code: Optional[int] = None,
        client_id: Optional[str] = None,
        **kwargs,
    ):
        details = kwargs.pop("details", {})
        if api_key_masked:
            details["api_key"] = api_key_masked
        if status_code is not None:
            details["status_code"] = status_code
        if client_id:
            details["client_id"] = client_id
        super().__init__(message, details=details, **kwargs)


# ============================================================
# 🚀 SECURITY ENGINE ERRORS (TrianSec Problem)
# ============================================================

class SecurityEngineError(SecurityError):
    """
    Raised when communication with the security engine fails.
    
    OWNER: TrianSec Service
    - Network issues
    - Service downtime
    - HTTP errors (5xx)
    
    SDK Action:
        - Use fallback action (allow or block)
        - Log with appropriate level
        - Notify operations
    """
    
    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        response_body: Optional[str] = None,
        **kwargs,
    ):
        details = kwargs.pop("details", {})
        if status_code is not None:
            details["status_code"] = status_code
        if response_body is not None:
            details["response_body"] = response_body[:500]  # Truncate
        super().__init__(message, details=details, **kwargs)


class SecurityEngineTimeoutError(SecurityEngineError):
    """
    Raised when the security engine request times out.
    
    OWNER: TrianSec Service / Network
    - Request exceeds configured timeout
    - Slow network response
    - Service overloaded
    
    SDK Action:
        - Retry with exponential backoff
        - Use fallback action if retries exhausted
    """
    
    def __init__(
        self,
        message: str = "Security engine request timed out",
        timeout_seconds: Optional[float] = None,
        **kwargs,
    ):
        details = kwargs.pop("details", {})
        if timeout_seconds is not None:
            details["timeout_seconds"] = timeout_seconds
        super().__init__(message, details=details, **kwargs)


class SecurityEngineUnavailableError(SecurityEngineError):
    """
    Raised when the security engine is unavailable.
    
    OWNER: TrianSec Service
    - Service is down
    - Connection refused
    - DNS resolution failure
    
    SDK Action:
        - Use fallback action immediately
        - No retry needed (service is down)
    """
    
    def __init__(
        self,
        message: str = "Security engine is unavailable",
        engine_url: Optional[str] = None,
        **kwargs,
    ):
        details = kwargs.pop("details", {})
        if engine_url:
            details["engine_url"] = engine_url
        super().__init__(message, details=details, **kwargs)


class SecurityEngineInvalidResponseError(SecurityEngineError):
    """
    Raised when the security engine returns an invalid response.
    
    OWNER: TrianSec Service
    - Malformed JSON
    - Missing required fields
    - Invalid data types
    
    SDK Action:
        - Log ERROR
        - Use fallback action
    """
    
    def __init__(
        self,
        message: str = "Invalid response from security engine",
        response_body: Optional[str] = None,
        validation_errors: Optional[List[str]] = None,
        **kwargs,
    ):
        details = kwargs.pop("details", {})
        if validation_errors:
            details["validation_errors"] = validation_errors
        super().__init__(message, response_body=response_body, details=details, **kwargs)


# ============================================================
# 🚦 RATE LIMIT ERRORS (Client Problem)
# ============================================================

class RateLimitError(SecurityError):
    """
    Raised when rate limit is exceeded.
    
    OWNER: Client Application
    - Client's application sending too many requests
    - Need to implement better request throttling
    
    SDK Action:
        - Wait and retry with exponential backoff
        - Use retry_after from response if available
        - May need to slow down request rate
    """
    
    def __init__(
        self,
        message: str = "Rate limit exceeded",
        limit: Optional[int] = None,
        remaining: Optional[int] = None,
        reset_at: Optional[float] = None,
        retry_after: Optional[int] = None,
        **kwargs,
    ):
        details = kwargs.pop("details", {})
        if limit is not None:
            details["limit"] = limit
        if remaining is not None:
            details["remaining"] = remaining
        if reset_at is not None:
            details["reset_at"] = reset_at
        if retry_after is not None:
            details["retry_after"] = retry_after
        super().__init__(message, details=details, **kwargs)


# ============================================================
# 💾 CACHE ERRORS (Internal SDK Problem)
# ============================================================

class CacheError(SecurityError):
    """
    Raised when cache operations fail.
    
    OWNER: SDK / System
    - Cache read/write error
    - Cache full
    - Memory issues
    
    SDK Action:
        - Log ERROR
        - Bypass cache and continue (graceful degradation)
    """
    
    def __init__(
        self,
        message: str,
        cache_key: Optional[str] = None,
        operation: Optional[str] = None,
        **kwargs,
    ):
        details = kwargs.pop("details", {})
        if cache_key:
            details["cache_key"] = cache_key
        if operation:
            details["operation"] = operation
        super().__init__(message, details=details, **kwargs)


# ============================================================
# ✅ VALIDATION ERRORS (Developer Problem)
# ============================================================

class ValidationError(SecurityError):
    """
    Raised when input validation fails.
    
    OWNER: Developer
    - Developer sent invalid request data
    - Missing required fields
    - Invalid format
    
    Developer Fix:
        - Check request data structure
        - Ensure all required fields are present
        - Validate data types
    
    SDK Action:
        - Log ERROR
        - Return 400 to client (if applicable)
    """
    
    def __init__(
        self,
        message: str,
        field: Optional[str] = None,
        value: Optional[Any] = None,
        **kwargs,
    ):
        details = kwargs.pop("details", {})
        if field:
            details["field"] = field
        if value is not None:
            details["value"] = str(value)[:100]  # Truncate
        super().__init__(message, details=details, **kwargs)


# ============================================================
# 🔧 SDK ERRORS (TrianSec SDK Problem)
# ============================================================

class SDKError(SecurityError):
    """
    Raised when an internal SDK error occurs.
    
    OWNER: TrianSec SDK Team
    - Unexpected error
    - Internal state inconsistency
    - Feature not implemented
    - SDK bug
    
    SDK Action:
        - Log CRITICAL
        - Use fallback action
        - Report to SDK maintainers
    """
    
    def __init__(
        self,
        message: str,
        component: Optional[str] = None,
        **kwargs,
    ):
        details = kwargs.pop("details", {})
        if component:
            details["component"] = component
        super().__init__(message, details=details, **kwargs)


# ============================================================
# 🔄 EXCEPTION HELPERS
# ============================================================

def raise_from_response(
    status_code: int,
    response_body: Optional[str] = None,
    request_uuid: Optional[str] = None,
    **kwargs,
) -> None:
    """
    Raise appropriate exception based on HTTP status code.
    
    Args:
        status_code: HTTP status code
        response_body: Response body (optional)
        request_uuid: Request UUID (optional)
        **kwargs: Additional arguments to pass to exception
    
    Raises:
        AuthenticationError: On 401/403 (CLIENT's API key issue)
        RateLimitError: On 429 (Client hitting limits)
        SecurityEngineError: On 5xx (TrianSec service issue)
    
    Examples:
        >>> raise_from_response(401, request_uuid="123")
        AuthenticationError: API key authentication failed
        
        >>> raise_from_response(429, request_uuid="123")
        RateLimitError: Rate limit exceeded
        
        >>> raise_from_response(503, request_uuid="123")
        SecurityEngineUnavailableError: Security engine is unavailable
    """
    if status_code == 401:
        raise AuthenticationError(
            message="API key authentication failed. Please check your TrianSec API key.",
            request_uuid=request_uuid,
            status_code=status_code,
            **kwargs,
        )
    elif status_code == 403:
        raise AuthenticationError(
            message="API key access forbidden. Please check your API key permissions.",
            request_uuid=request_uuid,
            status_code=status_code,
            **kwargs,
        )
    elif status_code == 429:
        raise RateLimitError(
            message="Rate limit exceeded. Please slow down your requests.",
            request_uuid=request_uuid,
            **kwargs,
        )
    elif status_code >= 500:
        raise SecurityEngineUnavailableError(
            message=f"Security engine returned {status_code}",
            request_uuid=request_uuid,
            status_code=status_code,
            response_body=response_body,
            **kwargs,
        )
    else:
        raise SecurityEngineError(
            message=f"Security engine returned {status_code}",
            request_uuid=request_uuid,
            status_code=status_code,
            response_body=response_body,
            **kwargs,
        )


def wrap_exception(
    exception: Exception,
    message: Optional[str] = None,
    request_uuid: Optional[str] = None,
    **kwargs,
) -> SecurityError:
    """
    Wrap an exception in a SecurityError.
    
    Args:
        exception: Original exception
        message: Custom message (optional)
        request_uuid: Request UUID (optional)
        **kwargs: Additional arguments to pass to SecurityError
    
    Returns:
        Wrapped SecurityError
    
    Examples:
        >>> try:
        ...     # Some operation
        ... except ConnectionError as e:
        ...     raise wrap_exception(e, "Failed to connect to security engine")
    """
    error_message = message or str(exception)
    return SecurityError(
        message=error_message,
        request_uuid=request_uuid,
        original_exception=exception,
        **kwargs,
    )


def is_retryable_error(exception: Exception) -> bool:
    """
    Check if an exception indicates a retryable error.
    
    Args:
        exception: Exception to check
    
    Returns:
        True if the error is retryable
    
    Examples:
        >>> is_retryable_error(SecurityEngineTimeoutError())
        True
        >>> is_retryable_error(SecurityEngineUnavailableError())
        False  # Service is down, don't retry
        >>> is_retryable_error(RateLimitError())
        True  # Wait and retry
        >>> is_retryable_error(AuthenticationError())
        False  # Client problem, retry won't fix
    """
    retryable_types = (
        SecurityEngineTimeoutError,
        RateLimitError,
    )
    
    if isinstance(exception, retryable_types):
        return True
    
    # Network/connection errors are retryable
    if isinstance(exception, (ConnectionError, TimeoutError)):
        return True
    
    return False


def is_blockable_error(exception: Exception) -> bool:
    """
    Check if an exception should trigger a block (fail closed).
    
    Args:
        exception: Exception to check
    
    Returns:
        True if the error should cause a block
    
    Examples:
        >>> is_blockable_error(AuthenticationError())
        True  # API key invalid - should block
        >>> is_blockable_error(ConfigurationError())
        True  # Misconfigured - should block
        >>> is_blockable_error(SecurityEngineTimeoutError())
        False  # Transient - use fallback
    """
    blockable_types = (
        AuthenticationError,
        ConfigurationError,
        SecurityEngineInvalidResponseError,
    )
    
    if isinstance(exception, blockable_types):
        return True
    
    return False


def get_user_friendly_message(exception: Exception) -> str:
    """
    Get a user-friendly error message (for end users).
    
    IMPORTANT: This should NEVER expose internal details!
    
    Args:
        exception: Exception to convert
    
    Returns:
        User-friendly error message
    
    Examples:
        >>> get_user_friendly_message(AuthenticationError())
        'Service temporarily unavailable. Please try again later.'
        
        >>> get_user_friendly_message(RateLimitError())
        'Too many requests. Please wait a moment and try again.'
        
        >>> get_user_friendly_message(ConfigurationError())
        'Service temporarily unavailable. Please try again later.'
    """
    if isinstance(exception, AuthenticationError):
        # NEVER expose API key issues to users
        return "Service temporarily unavailable. Please try again later."
    
    if isinstance(exception, RateLimitError):
        retry_after = exception.details.get("retry_after")
        if retry_after:
            return f"Too many requests. Please wait {retry_after} seconds and try again."
        return "Too many requests. Please wait a moment and try again."
    
    if isinstance(exception, SecurityEngineError):
        return "Service temporarily unavailable. Please try again later."
    
    if isinstance(exception, ConfigurationError):
        # Developer problem - but users shouldn't know
        return "Service temporarily unavailable. Please try again later."
    
    # Generic fallback
    return "An unexpected error occurred. Please try again later."


# ============================================================
# 📋 EXPORTS
# ============================================================

__all__ = [
    # Base
    "SecurityError",
    
    # Configuration (Developer problem)
    "ConfigurationError",
    
    # Authentication (Client problem - NEVER expose to users!)
    "AuthenticationError",
    
    # Security Engine (TrianSec problem)
    "SecurityEngineError",
    "SecurityEngineTimeoutError",
    "SecurityEngineUnavailableError",
    "SecurityEngineInvalidResponseError",
    
    # Rate Limit (Client application problem)
    "RateLimitError",
    
    # Cache (Internal SDK problem)
    "CacheError",
    
    # Validation (Developer problem)
    "ValidationError",
    
    # SDK (TrianSec SDK problem)
    "SDKError",
    
    # Helpers
    "raise_from_response",
    "wrap_exception",
    "is_retryable_error",
    "is_blockable_error",
    "get_user_friendly_message",
]