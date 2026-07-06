"""
HTTP Client for TrianSec Security Engine.

This module provides the HTTP client that communicates with the TrianSec
security engine. The client handles:
- Sending request data to the security engine
- Receiving and parsing security decisions
- Retry logic with exponential backoff
- Timeout handling
- Error handling and response validation

The engine URL is HARDCODED in the SDK - clients don't configure it.
"""

import asyncio
import json
import logging
import time
from typing import Optional, Dict, Any, List
from urllib.parse import urljoin

import httpx

from triansec.constants import (
    API_ENDPOINT_ANALYZE,
    API_ENDPOINT_HEALTH,
    DEFAULT_ENGINE_URL,
    DEFAULT_RETRY_COUNT,
    DEFAULT_TIMEOUT,
    HEADER_API_KEY,
    HEADER_CONTENT_TYPE,
    HEADER_REQUEST_UUID,
    SDK_VERSION,
    USER_AGENT_SDK,
)
from triansec.exceptions import (
    AuthenticationError,
    ConfigurationError,
    RateLimitError,
    SecurityEngineError,
    SecurityEngineInvalidResponseError,
    SecurityEngineTimeoutError,
    SecurityEngineUnavailableError,
    raise_from_response,
    wrap_exception,
    is_retryable_error,
)
from triansec.logger import get_logger, log_performance
from triansec.utils import format_timestamp_iso
from triansec.models.response import SecurityDecision
from triansec.utils import (
    calculate_backoff,
    is_retryable_status_code,
    join_url,
    normalize_url,
)

logger = get_logger(__name__)


class SecurityClient:
    """
    HTTP client for TrianSec Security Engine.
    
    This client communicates with the security engine to get security decisions.
    The engine URL is hardcoded in the SDK - clients don't configure it.
    
    Attributes:
        api_key: Client's API key (provided by client)
        engine_url: Security engine URL (hardcoded in SDK)
        timeout: Request timeout in seconds
        retry_count: Number of retry attempts
        client: HTTP client instance
        enable_debug: Debug mode
    
    Usage:
        # Client provides API key
        client = SecurityClient(
            api_key="ts_live_xxxxx",
            timeout=5,
            retry_count=3
        )
        
        # Send request for analysis
        decision = await client.analyze(
            request_data=request_data,
            request_uuid="123e4567-e89b-12d3-a456-426614174000"
        )
    """
    
    def __init__(
        self,
        api_key: str,
        engine_url: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
        retry_count: int = DEFAULT_RETRY_COUNT,
        enable_debug: bool = False,
    ):
        """
        Initialize the security client.
        
        Args:
            api_key: Client's API key (required)
            engine_url: Security engine URL (defaults to hardcoded URL)
            timeout: Request timeout in seconds
            retry_count: Number of retry attempts
            enable_debug: Enable debug mode
        
        Raises:
            ConfigurationError: If API key is not provided
        """
        if not api_key:
            raise ConfigurationError(
                "API key is required. Please provide your TrianSec API key.",
                config_key="api_key"
            )
        
        self.api_key = api_key
        self.engine_url = engine_url or DEFAULT_ENGINE_URL
        self.timeout = timeout
        self.retry_count = retry_count
        self.enable_debug = enable_debug
        
        # Normalize engine URL
        self.engine_url = normalize_url(self.engine_url)
        
        # Build endpoints
        self.analyze_endpoint = join_url(self.engine_url, API_ENDPOINT_ANALYZE)
        self.health_endpoint = join_url(self.engine_url, API_ENDPOINT_HEALTH)
        
        # Initialize HTTP client
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(
                timeout=timeout,
                connect=timeout,
                read=timeout,
                write=timeout,
            ),
            headers={
                HEADER_API_KEY: api_key,
                HEADER_CONTENT_TYPE: "application/json",
                "User-Agent": USER_AGENT_SDK,
            },
            limits=httpx.Limits(
                max_keepalive_connections=10,
                max_connections=100,
            ),
            follow_redirects=True,
        )
        
        logger.info(
            f"SecurityClient initialized: "
            f"engine_url={self.engine_url}, "
            f"timeout={self.timeout}s, "
            f"retry_count={self.retry_count}"
        )
    
    # ============================================================
    # 🔄 MAIN REQUEST METHODS
    # ============================================================
    
    async def analyze(
        self,
        request_data: Dict[str, Any],
        request_uuid: Optional[str] = None,
    ) -> SecurityDecision:
        """
        Send request to security engine for analysis.
        
        This is the main method used by the SDK middleware to get security decisions.
        The request is sent to the security engine with retry logic.
        
        Args:
            request_data: Request metadata (IP, User-Agent, endpoint, etc.)
            request_uuid: Request UUID for tracing
        
        Returns:
            SecurityDecision: Decision from security engine
        
        Raises:
            AuthenticationError: Invalid API key
            RateLimitError: Rate limit exceeded
            SecurityEngineError: Engine error
            SecurityEngineTimeoutError: Request timeout
            SecurityEngineUnavailableError: Engine unavailable
        
        Examples:
            >>> decision = await client.analyze(
            ...     request_data={
            ...         "ip_address": "192.168.1.1",
            ...         "user_agent": "Mozilla/5.0",
            ...         "endpoint": "/api/login",
            ...         "method": "POST"
            ...     },
            ...     request_uuid="123e4567-e89b-12d3-a456-426614174000"
            ... )
            >>> decision.action
            'allow'
        """
        start_time = time.time()
        last_error = None
        
        # Build request payload
        payload = self._build_payload(request_data, request_uuid)
        
        # Log request (debug only)
        if self.enable_debug:
            logger.debug(
                f"Sending analyze request: "
                f"endpoint={self.analyze_endpoint}, "
                f"request_uuid={request_uuid}"
            )
        
        # Attempt with retries
        for attempt in range(self.retry_count + 1):
            try:
                response = await self._send_analyze_request(payload, request_uuid)
                
                # Parse and validate response
                decision = self._parse_response(response, request_uuid)
                
                # Log performance
                duration_ms = (time.time() - start_time) * 1000
                log_performance(
                    logger,
                    "engine_analyze",
                    duration_ms,
                    request_uuid,
                    action=decision.action,
                    attempt=attempt + 1,
                )
                
                if self.enable_debug:
                    logger.debug(
                        f"Analyze response: "
                        f"action={decision.action}, "
                        f"risk={decision.risk_score:.2f}, "
                        f"trust={decision.trust_score:.2f}, "
                        f"request_uuid={request_uuid}"
                    )
                
                return decision
                
            except (SecurityEngineTimeoutError, SecurityEngineUnavailableError) as e:
                last_error = e
                if attempt < self.retry_count:
                    # Calculate backoff delay
                    delay = calculate_backoff(attempt)
                    logger.warning(
                        f"Analyze attempt {attempt + 1} failed: {e}. "
                        f"Retrying in {delay:.2f}s... "
                        f"request_uuid={request_uuid}"
                    )
                    await asyncio.sleep(delay)
                    continue
                else:
                    logger.error(
                        f"Analyze failed after {self.retry_count + 1} attempts: {e}. "
                        f"request_uuid={request_uuid}"
                    )
                    raise
                    
            except (AuthenticationError, RateLimitError) as e:
                # Don't retry these errors
                logger.error(
                    f"Analyze failed (non-retryable): {e}. "
                    f"request_uuid={request_uuid}"
                )
                raise
                
            except Exception as e:
                last_error = e
                if attempt < self.retry_count and is_retryable_error(e):
                    delay = calculate_backoff(attempt)
                    logger.warning(
                        f"Analyze attempt {attempt + 1} failed: {e}. "
                        f"Retrying in {delay:.2f}s... "
                        f"request_uuid={request_uuid}"
                    )
                    await asyncio.sleep(delay)
                    continue
                else:
                    logger.error(
                        f"Analyze failed: {e}. "
                        f"request_uuid={request_uuid}"
                    )
                    raise wrap_exception(
                        e,
                        message="Failed to get security decision",
                        request_uuid=request_uuid,
                    )
        
        # If we get here, all retries failed
        raise last_error or SecurityEngineUnavailableError(
            message="All retry attempts exhausted",
            request_uuid=request_uuid,
        )
    
    async def health_check(self) -> bool:
        """
        Check if the security engine is healthy.
        
        Returns:
            True if healthy, False otherwise
        
        Examples:
            >>> is_healthy = await client.health_check()
            >>> if is_healthy:
            ...     print("Engine is healthy")
        """
        try:
            response = await self.client.get(
                self.health_endpoint,
                timeout=5.0,
            )
            return response.status_code == 200
        except Exception:
            return False
    
    # ============================================================
    # 🔧 INTERNAL REQUEST METHODS
    # ============================================================
    
    async def _send_analyze_request(
        self,
        payload: Dict[str, Any],
        request_uuid: Optional[str] = None,
    ) -> httpx.Response:
        """
        Send the analyze request to the security engine.
        
        Args:
            payload: Request payload
            request_uuid: Request UUID for tracing
        
        Returns:
            HTTP response
        
        Raises:
            SecurityEngineTimeoutError: Request timeout
            SecurityEngineUnavailableError: Engine unavailable
            SecurityEngineError: Other engine errors
        """
        try:
            # Build headers
            headers = {}
            if request_uuid:
                headers[HEADER_REQUEST_UUID] = request_uuid
            
            # Send request
            response = await self.client.post(
                self.analyze_endpoint,
                json=payload,
                headers=headers,
            )
            
            # Check status code
            if response.status_code >= 400:
                self._handle_error_response(response, request_uuid)
            
            return response
            
        except httpx.TimeoutException as e:
            raise SecurityEngineTimeoutError(
                message=f"Security engine request timed out after {self.timeout}s",
                timeout_seconds=self.timeout,
                request_uuid=request_uuid,
                original_exception=e,
            )
        except httpx.ConnectError as e:
            raise SecurityEngineUnavailableError(
                message=f"Failed to connect to security engine: {e}",
                engine_url=self.engine_url,
                request_uuid=request_uuid,
                original_exception=e,
            )
        except httpx.HTTPError as e:
            raise SecurityEngineError(
                message=f"HTTP error: {e}",
                request_uuid=request_uuid,
                original_exception=e,
            )
        except Exception as e:
            raise SecurityEngineError(
                message=f"Unexpected error: {e}",
                request_uuid=request_uuid,
                original_exception=e,
            )
    
    def _handle_error_response(
        self,
        response: httpx.Response,
        request_uuid: Optional[str] = None,
    ) -> None:
        """
        Handle error response from security engine.
        
        Args:
            response: HTTP response with error status
            request_uuid: Request UUID for tracing
        
        Raises:
            AuthenticationError: On 401/403
            RateLimitError: On 429
            SecurityEngineError: On other errors
        """
        status_code = response.status_code
        response_body = response.text[:500] if response.text else None
        
        # Try to parse error details from response
        error_details = None
        if response.text:
            try:
                error_data = response.json()
                error_details = error_data.get("detail") or error_data.get("message")
            except json.JSONDecodeError:
                pass
        
        # Raise appropriate exception
        if status_code == 401:
            raise AuthenticationError(
                message=error_details or "Invalid API key. Please check your TrianSec credentials.",
                status_code=status_code,
                request_uuid=request_uuid,
            )
        elif status_code == 403:
            raise AuthenticationError(
                message=error_details or "Access forbidden. Please check your API key permissions.",
                status_code=status_code,
                request_uuid=request_uuid,
            )
        elif status_code == 429:
            raise RateLimitError(
                message=error_details or "Rate limit exceeded. Please slow down your requests.",
                status_code=status_code,
                request_uuid=request_uuid,
            )
        elif status_code >= 500:
            raise SecurityEngineUnavailableError(
                message=error_details or f"Security engine returned {status_code}",
                status_code=status_code,
                response_body=response_body,
                request_uuid=request_uuid,
            )
        else:
            raise SecurityEngineError(
                message=error_details or f"Security engine returned {status_code}",
                status_code=status_code,
                response_body=response_body,
                request_uuid=request_uuid,
            )
    
    # ============================================================
    # 📦 REQUEST/RESPONSE BUILDERS & PARSERS
    # ============================================================
    
    def _build_payload(
        self,
        request_data: Dict[str, Any],
        request_uuid: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Build the request payload for the security engine.
        
        Args:
            request_data: Request metadata
            request_uuid: Request UUID for tracing
        
        Returns:
            Request payload dictionary
        """
        payload = {
            "request_uuid": request_uuid,
            "request_data": request_data,
            "sdk_version": SDK_VERSION,
        }
        
        # Add timestamp if not present
        if "timestamp" not in request_data:
            payload["request_data"]["timestamp"] = format_timestamp_iso()
        
        return payload
    
    def _parse_response(
        self,
        response: httpx.Response,
        request_uuid: Optional[str] = None,
    ) -> SecurityDecision:
        """
        Parse and validate security engine response.
        
        Args:
            response: HTTP response from security engine
            request_uuid: Request UUID for tracing
        
        Returns:
            SecurityDecision: Parsed decision
        
        Raises:
            SecurityEngineInvalidResponseError: Invalid response
        """
        try:
            data = response.json()
        except json.JSONDecodeError as e:
            raise SecurityEngineInvalidResponseError(
                message="Invalid JSON response from security engine",
                response_body=response.text[:500],
                request_uuid=request_uuid,
                original_exception=e,
            )
        
        # Validate required fields
        required_fields = ["action"]
        missing_fields = [f for f in required_fields if f not in data]
        if missing_fields:
            raise SecurityEngineInvalidResponseError(
                message=f"Missing required fields in response: {missing_fields}",
                response_body=json.dumps(data)[:500],
                request_uuid=request_uuid,
                validation_errors=[f"Missing field: {f}" for f in missing_fields],
            )
        
        # Validate action value
        if data["action"] not in ["allow", "block", "throttle"]:
            raise SecurityEngineInvalidResponseError(
                message=f"Invalid action value: {data['action']}",
                response_body=json.dumps(data)[:500],
                request_uuid=request_uuid,
                validation_errors=[f"Invalid action: {data['action']}"],
            )
        
        # Create SecurityDecision object
        try:
            return SecurityDecision(**data)
        except Exception as e:
            raise SecurityEngineInvalidResponseError(
                message=f"Invalid response data: {e}",
                response_body=json.dumps(data)[:500],
                request_uuid=request_uuid,
                original_exception=e,
            )
    
    # ============================================================
    # 🧹 CLEANUP
    # ============================================================
    
    async def close(self) -> None:
        """
        Close the HTTP client and release resources.
        
        Should be called when the client is no longer needed.
        
        Examples:
            >>> await client.close()
        """
        await self.client.aclose()
        logger.debug("SecurityClient closed")
    
    async def __aenter__(self):
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
    
    # ============================================================
    # 📊 STATS AND INFO
    # ============================================================
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get client statistics.
        
        Returns:
            Dictionary with client statistics
        
        Examples:
            >>> stats = client.get_stats()
            >>> stats["engine_url"]
            'https://api.triansec.com'
        """
        return {
            "engine_url": self.engine_url,
            "timeout": self.timeout,
            "retry_count": self.retry_count,
            "enable_debug": self.enable_debug,
            "sdk_version": SDK_VERSION,
        }
    
    def __repr__(self) -> str:
        """String representation of the client."""
        return (
            f"SecurityClient("
            f"engine_url={self.engine_url}, "
            f"timeout={self.timeout}, "
            f"retry_count={self.retry_count}"
            f")"
        )


# ============================================================
# 🔧 HELPER FUNCTIONS
# ============================================================

def create_client(
    api_key: str,
    engine_url: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
    retry_count: int = DEFAULT_RETRY_COUNT,
    enable_debug: bool = False,
) -> SecurityClient:
    """
    Create a SecurityClient instance.
    
    This is a convenience function for creating a client.
    
    Args:
        api_key: Client's API key
        engine_url: Security engine URL (defaults to hardcoded URL)
        timeout: Request timeout in seconds
        retry_count: Number of retry attempts
        enable_debug: Enable debug mode
    
    Returns:
        SecurityClient instance
    
    Examples:
        >>> client = create_client(
        ...     api_key="ts_live_xxxxx",
        ...     timeout=10,
        ...     retry_count=5
        ... )
    """
    return SecurityClient(
        api_key=api_key,
        engine_url=engine_url,
        timeout=timeout,
        retry_count=retry_count,
        enable_debug=enable_debug,
    )


# ============================================================
# 📋 EXPORTS
# ============================================================

__all__ = [
    "SecurityClient",
    "create_client",
]