"""
TrianSec Security Middleware.

This middleware intercepts incoming requests, sends them to the TrianSec
security engine for behavioral analysis, and applies the returned decision
(ALLOW, BLOCK, or THROTTLE) before the request reaches your application logic.

Usage:
    from fastapi import FastAPI
    from triansec import TriAnSec

    app = FastAPI()
    app.add_middleware(
        TriAnSec,
        api_key="ts_live_xxxxxxxxx",
    )
"""

import time
import uuid
from typing import Optional, List, Literal, Callable, Awaitable, Tuple

from fastapi import Request
from fastapi.responses import JSONResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware

from triansec.cache import cache_decision, get_cached_decision
from triansec.client import SecurityClient
from triansec.config import SecurityConfig, create_config
from triansec.constants import (
    CONTROL_PLANE_PREFIXES,
    DEFAULT_CACHE_TTL,
    DEFAULT_FALLBACK_ACTION,
    DEFAULT_TIMEOUT,
)
from triansec.exceptions import (
    AuthenticationError,
    ConfigurationError,
    SecurityEngineError,
)
from triansec.identity.resolver import extract_request_data
from triansec.logger import get_logger
from triansec.models.response import SecurityDecision

logger = get_logger(__name__)


class TriAnSec(BaseHTTPMiddleware):
    """
    TrianSec security middleware for FastAPI/Starlette.

    Intercepts requests, forwards them to the TrianSec security engine,
    and enforces security decisions (ALLOW, BLOCK, THROTTLE) before reaching
    your application logic.

    The middleware implements a fast decision path that delivers pre-computed
    security decisions from the Policy Manager with minimal latency.

    Attributes:
        config: Security configuration
        client: Security engine HTTP client
        fallback_action: Action when engine is unreachable ("allow" or "block")
        enable_cache: Enable local decision caching
        cache_ttl: Cache TTL in seconds
        enable_debug: Enable debug logging
        bypass_paths: Paths to bypass security checks

    Usage:
        from fastapi import FastAPI
        from triansec import TriAnSec

        app = FastAPI()

        # Option 1: Direct with parameters
        app.add_middleware(
            TriAnSec,
            api_key="ts_live_xxxxxxxxx",
            timeout=10,
            fallback_action="allow",
        )

        # Option 2: With config object
        from triansec import SecurityConfig
        config = SecurityConfig(api_key="ts_live_xxxxxxxxx")
        app.add_middleware(TriAnSec, config=config)
    """

    def __init__(
        self,
        app,
        api_key: Optional[str] = None,
        engine_url: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
        retry_count: int = 3,
        fallback_action: Literal["allow", "block"] = DEFAULT_FALLBACK_ACTION,
        enable_cache: bool = True,
        cache_ttl: int = DEFAULT_CACHE_TTL,
        cache_maxsize: int = 1000,
        enable_debug: bool = False,
        bypass_paths: Optional[List[str]] = None,
        config: Optional[SecurityConfig] = None,
        **kwargs,
    ):
        """
        Initialize the TrianSec middleware.

        Args:
            app: FastAPI/Starlette application instance
            api_key: TrianSec API key (can be loaded from config)
            engine_url: Security engine URL (defaults to hardcoded URL)
            timeout: Request timeout in seconds
            retry_count: Number of retry attempts
            fallback_action: Action when engine is unreachable ("allow" or "block")
            enable_cache: Enable local caching of decisions
            cache_ttl: Cache TTL in seconds
            cache_maxsize: Maximum cache entries
            enable_debug: Enable debug logging
            bypass_paths: List of path prefixes to bypass security
            config: SecurityConfig instance (overrides individual parameters)
            **kwargs: Additional configuration options

        Raises:
            ConfigurationError: If API key is not provided
        """
        super().__init__(app)

        # Load configuration
        if config is not None:
            self.config = config
        else:
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

        # Validate configuration
        self.config.raise_if_invalid()

        # Initialize security client
        self.client = SecurityClient(
            api_key=self.config.api_key,
            engine_url=self.config.engine_url,
            timeout=self.config.timeout,
            retry_count=self.config.retry_count,
            enable_debug=self.config.enable_debug,
        )

        # Use default bypass paths if none provided
        self.bypass_paths = self.config.bypass_paths or CONTROL_PLANE_PREFIXES

        # Cache TTL in seconds (convert to milliseconds for cachetools)
        self.cache_ttl_ms = self.config.cache_ttl * 1000

        logger.info(
            f"TriAnSec middleware initialized: "
            f"engine_url={self.config.get_engine_url_masked()}, "
            f"fallback_action={self.config.fallback_action}, "
            f"cache_enabled={self.config.enable_cache}, "
            f"debug={self.config.enable_debug}"
        )

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """
        Process incoming request through security pipeline.

        FAST DECISION PATH:
        1. Extract identity and request signals
        2. Check local cache for pre-computed decision
        3. Send to security engine for fast evaluation
        4. Apply decision immediately (ALLOW, BLOCK, THROTTLE)
        5. Return response to client

        All heavy processing (feature engineering, risk scoring, reputation updates)
        happens on the security engine server, ensuring sub-15ms latency for the SDK.

        Args:
            request: FastAPI Request object
            call_next: Next middleware or route handler

        Returns:
            Response: Security-enforced response
        """
        start_time = time.time()
        request_uuid = str(uuid.uuid4())
        request.state.request_uuid = request_uuid

        timings = {}
        decision = None
        from_cache = False

        logger.info(
            f"{request.method} {request.url.path} | "
            f"req_uuid={request_uuid}"
        )

        try:
            # ── 1. BYPASS CHECK ──────────────────────────────────────────────
            if self._should_bypass(request):
                timings['total'] = time.time() - start_time
                response = await call_next(request)
                response.headers["X-Request-UUID"] = request_uuid
                response.headers["X-Process-Time"] = f"{timings['total']:.4f}"
                response.headers["X-Security-Status"] = "bypassed"

                logger.info(
                    f"BYPASS: {request.url.path} | "
                    f"total={timings['total']:.3f}s | "
                    f"req_uuid={request_uuid}"
                )
                return response

            # ── 2. EXTRACT IDENTITY (FAST) ──────────────────────────────────
            t0 = time.time()
            request_data = extract_request_data(request)
            timings['identity_extraction'] = time.time() - t0

            # ── 3. FAST DECISION PATH: CHECK CACHE ──────────────────────────
            if self.config.enable_cache:
                t0 = time.time()
                cache_key = self._generate_cache_key(request_data)
                cached_decision = get_cached_decision(cache_key)

                if cached_decision is not None:
                    decision = cached_decision
                    from_cache = True
                    timings['cache_check'] = time.time() - t0
                    logger.debug(f"Fast path cache HIT: {cache_key}")

            # ── 4. FAST DECISION PATH: SEND TO SECURITY ENGINE ──────────────
            if decision is None:
                t0 = time.time()
                try:
                    decision = await self.client.analyze(
                        request_data=request_data,
                        request_uuid=request_uuid,
                    )
                    timings['engine_fast_path'] = time.time() - t0

                    # Cache decision for future fast path lookups
                    if self.config.enable_cache:
                        cache_key = self._generate_cache_key(request_data)
                        cache_decision(cache_key, decision, ttl=self.cache_ttl_ms)

                    logger.debug(
                        f"Fast path decision received: action={decision.action} | "
                        f"latency={timings['engine_fast_path']*1000:.2f}ms"
                    )

                except SecurityEngineError as e:
                    timings['engine_fast_path'] = time.time() - t0
                    logger.warning(
                        f"Fast path engine error: {e} | "
                        f"fallback_action={self.config.fallback_action} | "
                        f"req_uuid={request_uuid}"
                    )
                    return await self._handle_engine_error(
                        request=request,
                        call_next=call_next,
                        request_uuid=request_uuid,
                        start_time=start_time,
                        timings=timings,
                    )

                except AuthenticationError as e:
                    logger.error(f"Authentication error: {e} | req_uuid={request_uuid}")
                    return await self._handle_authentication_error(
                        request_uuid=request_uuid,
                        start_time=start_time,
                    )

            # ── 5. FAST DECISION APPLICATION ──────────────────────────────────
            timings['total'] = time.time() - start_time

            # Log fast decision
            logger.info(
                f"FAST DECISION: {request.method} {request.url.path} | "
                f"action={decision.action} | "
                f"cache={from_cache} | "
                f"total={timings['total']:.3f}s | "
                f"req_uuid={request_uuid}"
            )

            # Apply fast decision
            if decision.action == "block":
                return await self._handle_block(
                    request=request,
                    decision=decision,
                    request_uuid=request_uuid,
                    start_time=start_time,
                    timings=timings,
                )

            if decision.action == "throttle":
                return await self._handle_throttle(
                    request=request,
                    call_next=call_next,
                    decision=decision,
                    request_uuid=request_uuid,
                    start_time=start_time,
                    timings=timings,
                )

            # ALLOW
            return await self._handle_allow(
                request=request,
                call_next=call_next,
                decision=decision,
                request_uuid=request_uuid,
                start_time=start_time,
                timings=timings,
            )

        except Exception as e:
            logger.exception(f"Unexpected middleware error: {e} | req_uuid={request_uuid}")
            return await self._handle_unexpected_error(
                request=request,
                call_next=call_next,
                request_uuid=request_uuid,
                start_time=start_time,
            )

    # ── FAST DECISION HELPER ──────────────────────────────────────────────────

    async def _fast_decision(
        self,
        blocked: bool,
        throttled: bool,
        risk_score: float,
    ) -> Tuple[str, str]:
        """
        Fast path - applies pre-computed decisions from the security engine.

        This function mirrors your backend's _fast_decision() logic.
        It applies decisions already computed by the Policy Manager.

        Args:
            blocked: Whether the identity is blocked
            throttled: Whether the identity is throttled
            risk_score: Pre-computed risk score

        Returns:
            Tuple of (action, reason)
        """
        if blocked:
            return "block", "Identity blocked due to policy violation"

        if throttled:
            return "throttle", "Identity is rate-limited (policy enforced)"

        return "allow", "Identity is not under any active restriction"

    # ── DECISION HANDLERS ────────────────────────────────────────────────────

    async def _handle_allow(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
        decision: SecurityDecision,
        request_uuid: str,
        start_time: float,
        timings: dict,
    ) -> Response:
        """Handle ALLOW decision - pass request through."""
        t0 = time.time()
        response = await call_next(request)
        timings['call_next'] = time.time() - t0
        process_time = time.time() - start_time

        response.headers["X-Request-UUID"] = request_uuid
        response.headers["X-Process-Time"] = f"{process_time:.4f}"
        response.headers["X-Security-Status"] = "allow"

        timings['total'] = process_time

        logger.debug(
            f"ALLOW: {request.url.path} | "
            f"total={process_time:.3f}s | "
            f"timings={timings} | "
            f"req_uuid={request_uuid}"
        )

        return response

    async def _handle_throttle(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
        decision: SecurityDecision,
        request_uuid: str,
        start_time: float,
        timings: dict,
    ) -> Response:
        """Handle THROTTLE decision - add throttle headers and pass through."""
        t0 = time.time()
        response = await call_next(request)
        timings['call_next'] = time.time() - t0
        process_time = time.time() - start_time

        retry_after = decision.retry_after or 60
        response.headers["X-Request-UUID"] = request_uuid
        response.headers["X-Process-Time"] = f"{process_time:.4f}"
        response.headers["X-Security-Status"] = "throttle"
        response.headers["X-Throttled"] = "true"
        response.headers["X-RateLimit-Limit"] = "100"
        response.headers["X-RateLimit-Remaining"] = "0"
        response.headers["X-RateLimit-Reset"] = str(retry_after)
        response.headers["Retry-After"] = str(retry_after)

        timings['total'] = process_time

        logger.info(
            f"THROTTLE: {request.url.path} | "
            f"total={process_time:.3f}s | "
            f"retry_after={retry_after} | "
            f"req_uuid={request_uuid}"
        )

        return response

    async def _handle_block(
        self,
        request: Request,
        decision: SecurityDecision,
        request_uuid: str,
        start_time: float,
        timings: dict,
    ) -> JSONResponse:
        """Handle BLOCK decision - return 429 response."""
        process_time = time.time() - start_time

        content = {
            "detail": decision.reason[0] if decision.reason else "Request blocked by security policy",
            "request_uuid": request_uuid,
            "block_duration": decision.block_duration,
        }

        headers = {
            "X-Request-UUID": request_uuid,
            "X-Process-Time": f"{process_time:.4f}",
            "X-Security-Status": "block",
            "X-RateLimit-Reset": "blocked",
            "Cache-Control": "no-cache, no-store, must-revalidate",
        }

        if decision.block_duration:
            headers["Retry-After"] = str(decision.block_duration)

        timings['total'] = process_time

        logger.info(
            f"BLOCK: {request.url.path} | "
            f"total={process_time:.3f}s | "
            f"reason={decision.reason} | "
            f"req_uuid={request_uuid}"
        )

        return JSONResponse(
            status_code=429,
            content=content,
            headers=headers,
        )

    # ── ERROR HANDLERS ──────────────────────────────────────────────────────

    async def _handle_engine_error(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
        request_uuid: str,
        start_time: float,
        timings: dict,
    ) -> Response:
        """Handle security engine errors with fallback action."""
        if self.config.fallback_action == "block":
            process_time = time.time() - start_time
            timings['total'] = process_time

            logger.warning(
                f"FALLBACK BLOCK: {request.url.path} | "
                f"total={process_time:.3f}s | "
                f"req_uuid={request_uuid}"
            )

            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Security service temporarily unavailable",
                    "request_uuid": request_uuid,
                },
                headers={
                    "X-Request-UUID": request_uuid,
                    "X-Process-Time": f"{process_time:.4f}",
                    "X-Security-Status": "fallback_block",
                    "Retry-After": "30",
                },
            )

        # Allow through on engine failure (fail open - default)
        process_time = time.time() - start_time
        response = await call_next(request)
        response.headers["X-Request-UUID"] = request_uuid
        response.headers["X-Process-Time"] = f"{process_time:.4f}"
        response.headers["X-Security-Status"] = "fallback_allow"
        timings['total'] = process_time

        logger.warning(
            f"FALLBACK ALLOW: {request.url.path} | "
            f"total={process_time:.3f}s | "
            f"req_uuid={request_uuid}"
        )

        return response

    async def _handle_authentication_error(
        self,
        request_uuid: str,
        start_time: float,
    ) -> JSONResponse:
        """
        Handle authentication errors.

        IMPORTANT: This should NEVER be exposed to end users!
        This is a CLIENT configuration issue, not a user issue.
        """
        process_time = time.time() - start_time

        # Log CRITICAL - Client's API key is invalid
        logger.critical(
            f"CLIENT API KEY AUTHENTICATION FAILED: "
            f"Please check your TrianSec API key configuration. "
            f"req_uuid={request_uuid}"
        )

        if self.config.fallback_action == "block":
            return JSONResponse(
                status_code=503,
                content={
                    "detail": "Service temporarily unavailable. Please try again later.",
                    "request_uuid": request_uuid,
                },
                headers={
                    "X-Request-UUID": request_uuid,
                    "X-Process-Time": f"{process_time:.4f}",
                    "X-Security-Status": "auth_error_block",
                },
            )

        # Allow through (fail open) with warning
        logger.warning(f"FALLBACK ALLOW: Authentication failed, allowing request through")
        return JSONResponse(
            status_code=503,
            content={
                "detail": "Service temporarily unavailable. Please try again later.",
                "request_uuid": request_uuid,
            },
            headers={
                "X-Request-UUID": request_uuid,
                "X-Process-Time": f"{process_time:.4f}",
                "X-Security-Status": "auth_error_allow",
            },
        )

    async def _handle_unexpected_error(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
        request_uuid: str,
        start_time: float,
    ) -> Response:
        """Handle unexpected errors with fallback."""
        process_time = time.time() - start_time

        if self.config.fallback_action == "block":
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Security service error",
                    "request_uuid": request_uuid,
                },
                headers={
                    "X-Request-UUID": request_uuid,
                    "X-Process-Time": f"{process_time:.4f}",
                    "X-Security-Status": "error_block",
                },
            )

        response = await call_next(request)
        response.headers["X-Request-UUID"] = request_uuid
        response.headers["X-Process-Time"] = f"{process_time:.4f}"
        response.headers["X-Security-Status"] = "error_allow"
        return response

    # ── UTILITY METHODS ─────────────────────────────────────────────────────

    def _should_bypass(self, request: Request) -> bool:
        """Check if request path should bypass security."""
        path = request.url.path
        for prefix in self.bypass_paths:
            if path.startswith(prefix):
                return True
        return False

    def _generate_cache_key(self, request_data: dict) -> str:
        """Generate cache key from request data."""
        fingerprint = request_data.get("fingerprint", "")
        endpoint = request_data.get("endpoint", "")
        method = request_data.get("method", "")
        return f"triansec:decision:{fingerprint}:{method}:{endpoint}"

    # ── CLEANUP ─────────────────────────────────────────────────────────────

    async def close(self) -> None:
        """Clean up resources."""
        await self.client.close()
        logger.info("TriAnSec middleware closed")


# ============================================================
# 📋 EXPORTS
# ============================================================

__all__ = [
    "TriAnSec",
]