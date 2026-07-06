"""
Constants for TrianSec SDK.

This module contains all configuration constants, default values,
HTTP headers, and status codes used throughout the SDK.
"""

from typing import List

# ============================================================
# 🎯 DEFAULT CONFIGURATION
# ============================================================
# Default engine URL (hardcoded - clients don't configure this)

DEFAULT_ENGINE_URL: str = "https://api.triansec.com" 
# Default timeout for security engine requests (seconds)
DEFAULT_TIMEOUT: int = 5

# Default cache TTL (seconds) - 5 minutes
DEFAULT_CACHE_TTL: int = 300

# Default action when security engine is unreachable
# "allow" - Let requests through (fail open)
# "block" - Block requests (fail closed)
DEFAULT_FALLBACK_ACTION: str = "allow"

# Default number of retry attempts
DEFAULT_RETRY_COUNT: int = 3

# Default retry backoff factor
DEFAULT_RETRY_BACKOFF: float = 1.0

# Default maximum cache size (number of entries)
DEFAULT_CACHE_MAXSIZE: int = 1000

# Default WebSocket reconnect attempts
DEFAULT_WS_RECONNECT_ATTEMPTS: int = 5

# Default WebSocket reconnect delay (seconds)
DEFAULT_WS_RECONNECT_DELAY: int = 2


# ============================================================
# 🔒 BLOCK DURATIONS (TTL)
# ============================================================

# Block TTL range: 2 - 12 hours (in seconds)
BLOCK_TTL_MIN_HOURS: int = 2
BLOCK_TTL_MAX_HOURS: int = 12

# Block TTL in seconds (pre-calculated)
BLOCK_TTL_MIN_SECONDS: int = 7200   # 2 hours
BLOCK_TTL_MAX_SECONDS: int = 43200  # 12 hours

# Pre-defined block durations (in seconds)
BLOCK_DURATION_2H: int = 7200    # 2 hours
BLOCK_DURATION_4H: int = 14400   # 4 hours
BLOCK_DURATION_6H: int = 21600   # 6 hours
BLOCK_DURATION_8H: int = 28800   # 8 hours
BLOCK_DURATION_10H: int = 36000  # 10 hours
BLOCK_DURATION_12H: int = 43200  # 12 hours

# Default block duration when not specified (6 hours)
BLOCK_DURATION_DEFAULT: int = BLOCK_DURATION_6H


# ============================================================
# 🛤️ BYPASS PATHS
# ============================================================

# Control plane paths that bypass security checks
# These are typically authentication, dashboard, and management endpoints
CONTROL_PLANE_PREFIXES: List[str] = [
    "/api/auth",
    "/api/client",
    "/api-keys",
    "/api/settings",
    "/api/activity",
    "/api/client/keys",
    "/api/usage",
    "/api/dashboard",
    "/api/dashboard/stats",
    "/api/dashboard/traffic",
    "/api/dashboard/suspicious-users",
    "/api/dashboard/logs",
    "/api/developer",
    "/health",
    "/healthz",
    "/metrics",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/swagger",
    "/swagger-ui",
]


# ============================================================
# 📡 API ENDPOINTS
# ============================================================

# Security engine API endpoints
API_ENDPOINT_ANALYZE: str = "/v1/analyze"
API_ENDPOINT_HEALTH: str = "/v1/health"
API_ENDPOINT_CONFIG: str = "/v1/config"
API_ENDPOINT_METRICS: str = "/v1/metrics"
API_ENDPOINT_FEEDBACK: str = "/v1/feedback"

# WebSocket endpoints
WS_ENDPOINT_SECURITY: str = "/ws/security"
WS_ENDPOINT_ALERTS: str = "/ws/alerts"
WS_ENDPOINT_STATS: str = "/ws/stats"


# ============================================================
# 🔑 HTTP HEADERS
# ============================================================

# Request headers
HEADER_API_KEY: str = "X-API-Key"
HEADER_REQUEST_UUID: str = "X-Request-UUID"
HEADER_CONTENT_TYPE: str = "Content-Type"
HEADER_ACCEPT: str = "Accept"
HEADER_USER_AGENT: str = "User-Agent"
HEADER_X_FORWARDED_FOR: str = "X-Forwarded-For"
HEADER_X_REAL_IP: str = "X-Real-IP"

# Response headers
HEADER_PROCESS_TIME: str = "X-Process-Time"
HEADER_SECURITY_STATUS: str = "X-Security-Status"
HEADER_THROTTLED: str = "X-Throttled"
HEADER_TRUST_SCORE: str = "X-Trust-Score"
HEADER_RISK_SCORE: str = "X-Risk-Score"
HEADER_SUSPICION_SCORE: str = "X-Suspicion-Score"

# Rate limit headers
HEADER_RATE_LIMIT_LIMIT: str = "X-RateLimit-Limit"
HEADER_RATE_LIMIT_REMAINING: str = "X-RateLimit-Remaining"
HEADER_RATE_LIMIT_RESET: str = "X-RateLimit-Reset"
HEADER_RETRY_AFTER: str = "Retry-After"

# Cache headers
HEADER_CACHE_CONTROL: str = "Cache-Control"
HEADER_CACHE_STATUS: str = "X-Cache-Status"

# Client identification
HEADER_CLIENT_ID: str = "X-Client-ID"
HEADER_SESSION_ID: str = "X-Session-ID"

# Cookie names
COOKIE_USER_ID: str = "X-TrianSec-User-ID"


# ============================================================
# 📊 RESPONSE STATUS CODES
# ============================================================

# Security decisions
STATUS_ALLOW: int = 200
STATUS_BLOCKED: int = 429
STATUS_THROTTLED: int = 429  # Same as blocked
STATUS_AUTH_ERROR: int = 401
STATUS_FORBIDDEN: int = 403
STATUS_INTERNAL_ERROR: int = 500
STATUS_SERVICE_UNAVAILABLE: int = 503

# Rate limiting
STATUS_TOO_MANY_REQUESTS: int = 429

# Success
STATUS_OK: int = 200
STATUS_CREATED: int = 201
STATUS_ACCEPTED: int = 202
STATUS_NO_CONTENT: int = 204


# ============================================================
# 🎯 DECISION TYPES
# ============================================================

# Security actions
ACTION_ALLOW: str = "allow"
ACTION_BLOCK: str = "block"
ACTION_THROTTLE: str = "throttle"
ACTION_BYPASS: str = "bypass"
ACTION_FALLBACK: str = "fallback"

# Security statuses
STATUS_ACTION_ALLOW: str = "allow"
STATUS_ACTION_BLOCK: str = "block"
STATUS_ACTION_THROTTLE: str = "throttle"
STATUS_ACTION_BYPASS: str = "bypassed"
STATUS_ACTION_FALLBACK_ALLOW: str = "fallback_allow"
STATUS_ACTION_FALLBACK_BLOCK: str = "fallback_block"
STATUS_ACTION_AUTH_ERROR: str = "auth_error"
STATUS_ACTION_ERROR: str = "error"


# ============================================================
# 💾 CACHE KEYS
# ============================================================

# Cache key prefixes
CACHE_KEY_PREFIX_DECISION: str = "triansec:decision:"
CACHE_KEY_PREFIX_IDENTITY: str = "triansec:identity:"
CACHE_KEY_PREFIX_CONFIG: str = "triansec:config:"
CACHE_KEY_PREFIX_WEBSOCKET: str = "triansec:websocket:"

# Cache TTL values (seconds)
CACHE_TTL_DECISION: int = 300        # 5 minutes
CACHE_TTL_IDENTITY: int = 3600       # 1 hour
CACHE_TTL_CONFIG: int = 600          # 10 minutes
CACHE_TTL_NEGATIVE: int = 60         # 1 minute


# ============================================================
# 🧠 IDENTITY EXTRACTION
# ============================================================

# Default values for identity extraction
DEFAULT_IP: str = "unknown"
DEFAULT_USER_AGENT: str = "unknown"
DEFAULT_FINGERPRINT: str = "unknown"
DEFAULT_USER_ID: str = "anonymous"

# Identity types
IDENTITY_TYPE_ANONYMOUS: str = "anonymous"
IDENTITY_TYPE_AUTHENTICATED: str = "authenticated"
IDENTITY_TYPE_COOKIE: str = "cookie"
IDENTITY_TYPE_JWT: str = "jwt"
IDENTITY_TYPE_FINGERPRINT: str = "fingerprint"
IDENTITY_TYPE_UUID: str = "uuid"


# ============================================================
# 🔄 RETRY & BACKOFF
# ============================================================

# Retryable HTTP status codes
RETRYABLE_STATUS_CODES: List[int] = [
    408,  # Request Timeout
    429,  # Too Many Requests
    500,  # Internal Server Error
    502,  # Bad Gateway
    503,  # Service Unavailable
    504,  # Gateway Timeout
]

# Retryable exception types (strings for isinstance checks)
RETRYABLE_EXCEPTIONS: List[str] = [
    "TimeoutError",
    "ConnectionError",
    "ConnectionRefusedError",
    "ConnectionResetError",
    "ConnectionAbortedError",
]


# ============================================================
# 📈 METRICS & MONITORING
# ============================================================

# Metric names
METRIC_REQUESTS: str = "triansec_requests_total"
METRIC_DECISIONS: str = "triansec_decisions_total"
METRIC_LATENCY: str = "triansec_request_latency_seconds"
METRIC_ERRORS: str = "triansec_errors_total"
METRIC_CACHE_HITS: str = "triansec_cache_hits_total"
METRIC_CACHE_MISSES: str = "triansec_cache_misses_total"

# Metric labels
LABEL_ACTION: str = "action"
LABEL_STATUS: str = "status"
LABEL_CACHE: str = "cache"
LABEL_ENDPOINT: str = "endpoint"
LABEL_METHOD: str = "method"


# ============================================================
# 🧪 LOGGING
# ============================================================

# Log levels
LOG_LEVEL_DEBUG: str = "DEBUG"
LOG_LEVEL_INFO: str = "INFO"
LOG_LEVEL_WARNING: str = "WARNING"
LOG_LEVEL_ERROR: str = "ERROR"
LOG_LEVEL_CRITICAL: str = "CRITICAL"

# Log format
LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_DATE_FORMAT: str = "%Y-%m-%d %H:%M:%S"


# ============================================================
# 🌐 ENVIRONMENT VARIABLES
# ============================================================

# Environment variable names
ENV_API_KEY: str = "TRIANSEC_API_KEY"
ENV_ENGINE_URL: str = "TRIANSEC_ENGINE_URL"
ENV_TIMEOUT: str = "TRIANSEC_TIMEOUT"
ENV_RETRY_COUNT: str = "TRIANSEC_RETRY_COUNT"
ENV_FALLBACK_ACTION: str = "TRIANSEC_FALLBACK"
ENV_CACHE_ENABLED: str = "TRIANSEC_CACHE"
ENV_CACHE_TTL: str = "TRIANSEC_CACHE_TTL"
ENV_DEBUG: str = "TRIANSEC_DEBUG"
ENV_WEBSOCKET_ENABLED: str = "TRIANSEC_WEBSOCKET"
ENV_WEBSOCKET_URL: str = "TRIANSEC_WEBSOCKET_URL"
ENV_LOG_LEVEL: str = "TRIANSEC_LOG_LEVEL"
ENV_LOG_FORMAT: str = "TRIANSEC_LOG_FORMAT"


# ============================================================
# 🏷️ API KEY FORMAT
# ============================================================

# API key prefix format: ts_{environment}_{random}
API_KEY_PREFIX_LIVE: str = "ts_live_"
API_KEY_PREFIX_TEST: str = "ts_test_"
API_KEY_PREFIX_DEV: str = "ts_dev_"

# API key length (excluding prefix)
API_KEY_RANDOM_LENGTH: int = 48  # 48 hex characters = 24 bytes

# API key validation regex pattern
API_KEY_PATTERN: str = r"^ts_(live|test|dev)_[a-f0-9]{48}$"


# ============================================================
# 🔒 SECURITY CONSTANTS
# ============================================================

# Maximum request body size for preview (bytes)
MAX_BODY_PREVIEW_SIZE: int = 1024  # 1KB

# Maximum number of headers to forward
MAX_HEADERS_FORWARD: int = 50

# Sensitive headers to redact
SENSITIVE_HEADERS: List[str] = [
    "authorization",
    "cookie",
    "x-api-key",
    "x-auth-token",
    "set-cookie",
]

# Maximum number of query params to forward
MAX_QUERY_PARAMS: int = 100


# ============================================================
# 🌍 MIME TYPES
# ============================================================

# JSON content types
CONTENT_TYPE_JSON: str = "application/json"
CONTENT_TYPE_JSON_UTF8: str = "application/json; charset=utf-8"

# Form content types
CONTENT_TYPE_FORM: str = "application/x-www-form-urlencoded"
CONTENT_TYPE_MULTIPART: str = "multipart/form-data"

# Text content types
CONTENT_TYPE_TEXT: str = "text/plain"
CONTENT_TYPE_HTML: str = "text/html"
CONTENT_TYPE_XML: str = "application/xml"


# ============================================================
# 🔄 WEBSOCKET MESSAGE TYPES
# ============================================================

# WebSocket message types
WS_MSG_TYPE_ALERT: str = "alert"
WS_MSG_TYPE_STATS: str = "stats"
WS_MSG_TYPE_DECISION: str = "decision"
WS_MSG_TYPE_HEARTBEAT: str = "heartbeat"
WS_MSG_TYPE_ERROR: str = "error"
WS_MSG_TYPE_CONFIG: str = "config"

# WebSocket message payload keys
WS_PAYLOAD_TYPE: str = "type"
WS_PAYLOAD_DATA: str = "data"
WS_PAYLOAD_TIMESTAMP: str = "timestamp"


# ============================================================
# 📊 DASHBOARD CONSTANTS
# ============================================================

# Default time windows (seconds)
DEFAULT_TIME_WINDOW_15M: int = 900   # 15 minutes
DEFAULT_TIME_WINDOW_1H: int = 3600   # 1 hour
DEFAULT_TIME_WINDOW_24H: int = 86400 # 24 hours

# Default pagination
DEFAULT_PAGE_SIZE: int = 20
DEFAULT_MAX_PAGE_SIZE: int = 100
DEFAULT_PAGE: int = 1

# Risk thresholds
RISK_THRESHOLD_HIGH: float = 0.8
RISK_THRESHOLD_MEDIUM: float = 0.5
RISK_THRESHOLD_LOW: float = 0.2

# Trust thresholds
TRUST_THRESHOLD_HIGH: float = 0.7
TRUST_THRESHOLD_MEDIUM: float = 0.4
TRUST_THRESHOLD_LOW: float = 0.2


# ============================================================
# 🎯 PERFORMANCE TARGETS
# ============================================================

# Fast path latency target (milliseconds)
FAST_PATH_LATENCY_TARGET_MS: int = 15

# Cache decision latency target (milliseconds)
CACHE_HIT_LATENCY_TARGET_MS: int = 1

# Engine request latency target (milliseconds)
ENGINE_REQUEST_LATENCY_TARGET_MS: int = 50

# Total middleware overhead target (milliseconds)
TOTAL_OVERHEAD_TARGET_MS: int = 100


# ============================================================
# 🧪 TESTING CONSTANTS
# ============================================================

# Mock decision responses for testing
MOCK_DECISION_ALLOW: dict = {
    "action": "allow",
    "trust_score": 0.85,
    "risk_score": 0.12,
    "suspicion_score": 0.15,
    "reason": ["Normal behavior pattern"],
    "request_uuid": "test-uuid",
}

MOCK_DECISION_BLOCK: dict = {
    "action": "block",
    "trust_score": 0.12,
    "risk_score": 0.89,
    "suspicion_score": 0.91,
    "reason": [
        "High request burst",
        "Poor historical reputation",
        "Multiple previous violations"
    ],
    "request_uuid": "test-uuid",
    "block_duration": BLOCK_DURATION_DEFAULT,
}

MOCK_DECISION_THROTTLE: dict = {
    "action": "throttle",
    "trust_score": 0.35,
    "risk_score": 0.65,
    "suspicion_score": 0.70,
    "reason": ["Suspicious activity detected"],
    "request_uuid": "test-uuid",
    "retry_after": 60,
}


# ============================================================
# 📦 VERSION
# ============================================================

# SDK version - will be updated on release
SDK_VERSION: str = "0.1.3"

# User-Agent for HTTP requests
USER_AGENT_SDK: str = f"TrianSec-SDK/{SDK_VERSION}"


# ============================================================
# ⚠️ NOTE: NO FUNCTIONS OR LOGIC IN THIS FILE
# ============================================================
# This file contains ONLY constants.
# All helper functions should go in utils.py or validators.py.