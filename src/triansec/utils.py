"""
Utility functions for TrianSec SDK.

This module contains helper functions for:
- Request/response processing
- Data validation
- Formatting and parsing
- Security utilities
- Common operations
"""

import time
import json
import hashlib
import re
from typing import Optional, Dict, Any, List, Union
from datetime import datetime, timezone
from ipaddress import ip_address, IPv4Address, IPv6Address

from triansec.constants import (
    BLOCK_TTL_MIN_SECONDS,
    BLOCK_TTL_MAX_SECONDS,
    DEFAULT_IP,
    DEFAULT_USER_AGENT,
    DEFAULT_FINGERPRINT,
    SENSITIVE_HEADERS,
    MAX_BODY_PREVIEW_SIZE,
    API_KEY_PATTERN,
    RETRYABLE_STATUS_CODES,
    RETRYABLE_EXCEPTIONS,
)


# ============================================================
# 🔒 BLOCK DURATION VALIDATION
# ============================================================

def validate_block_duration(duration_seconds: int) -> int:
    """
    Validate and clamp block duration to allowed range (2-12 hours).

    Args:
        duration_seconds: Desired block duration in seconds

    Returns:
        Validated duration clamped to [BLOCK_TTL_MIN_SECONDS, BLOCK_TTL_MAX_SECONDS]

    Examples:
        >>> validate_block_duration(3600)   # 1 hour → 7200 (2 hours min)
        7200
        >>> validate_block_duration(21600)  # 6 hours → 21600
        21600
        >>> validate_block_duration(86400)  # 24 hours → 43200 (12 hours max)
        43200
    """
    if duration_seconds < BLOCK_TTL_MIN_SECONDS:
        return BLOCK_TTL_MIN_SECONDS
    if duration_seconds > BLOCK_TTL_MAX_SECONDS:
        return BLOCK_TTL_MAX_SECONDS
    return duration_seconds


def is_valid_block_duration(duration_seconds: int) -> bool:
    """
    Check if a block duration is within allowed range.

    Args:
        duration_seconds: Block duration in seconds

    Returns:
        True if duration is between 2 and 12 hours

    Examples:
        >>> is_valid_block_duration(3600)   # 1 hour → False
        False
        >>> is_valid_block_duration(21600)  # 6 hours → True
        True
        >>> is_valid_block_duration(86400)  # 24 hours → False
        False
    """
    return BLOCK_TTL_MIN_SECONDS <= duration_seconds <= BLOCK_TTL_MAX_SECONDS


def get_block_duration_hours(duration_seconds: int) -> int:
    """
    Convert block duration from seconds to hours.

    Args:
        duration_seconds: Block duration in seconds

    Returns:
        Block duration in hours

    Examples:
        >>> get_block_duration_hours(21600)
        6
        >>> get_block_duration_hours(7200)
        2
    """
    return duration_seconds // 3600


def get_block_duration_seconds(hours: int) -> int:
    """
    Convert block duration from hours to seconds (with validation).

    Args:
        hours: Block duration in hours

    Returns:
        Block duration in seconds (clamped to valid range)

    Examples:
        >>> get_block_duration_seconds(6)
        21600
        >>> get_block_duration_seconds(1)   # Clamped to 2 hours
        7200
        >>> get_block_duration_seconds(24)  # Clamped to 12 hours
        43200
    """
    return validate_block_duration(hours * 3600)


def get_block_duration_description(duration_seconds: int) -> str:
    """
    Get human-readable description of block duration.

    Args:
        duration_seconds: Block duration in seconds

    Returns:
        Human-readable duration string

    Examples:
        >>> get_block_duration_description(21600)
        '6 hours'
        >>> get_block_duration_description(7200)
        '2 hours'
        >>> get_block_duration_description(3600)
        '1 hour'
    """
    hours = duration_seconds // 3600
    if hours == 1:
        return "1 hour"
    return f"{hours} hours"


# ============================================================
# 🧠 FINGERPRINT GENERATION
# ============================================================

def generate_fingerprint(ip: str, user_agent: str) -> str:
    """
    Generate a unique fingerprint from IP and User-Agent.

    Args:
        ip: IP address string
        user_agent: User-Agent header string

    Returns:
        SHA256 hex digest fingerprint

    Examples:
        >>> generate_fingerprint("192.168.1.1", "Mozilla/5.0")
        'a1b2c3d4e5f6...'
    """
    raw = f"{ip}:{user_agent}"
    return hashlib.sha256(raw.encode()).hexdigest()


def generate_behavioral_fingerprint(
    ip: str,
    user_agent: str,
    accept_language: Optional[str] = None,
    accept_encoding: Optional[str] = None,
    endpoint: Optional[str] = None,
) -> str:
    """
    Generate a behavioral fingerprint from multiple signals.

    Args:
        ip: IP address
        user_agent: User-Agent header
        accept_language: Accept-Language header (optional)
        accept_encoding: Accept-Encoding header (optional)
        endpoint: Request endpoint (optional)

    Returns:
        SHA256 hex digest fingerprint

    Examples:
        >>> generate_behavioral_fingerprint(
        ...     "192.168.1.1",
        ...     "Mozilla/5.0",
        ...     "en-US",
        ...     "gzip",
        ...     "/api/login"
        ... )
        'b2c3d4e5f6a7...'
    """
    parts = [
        ip or DEFAULT_IP,
        user_agent or DEFAULT_USER_AGENT,
        accept_language or "",
        accept_encoding or "",
        endpoint or "",
    ]
    raw = ":".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()


# ============================================================
# 🌐 IP ADDRESS HELPERS
# ============================================================

def extract_ip_from_headers(headers: Dict[str, str]) -> str:
    """
    Extract real client IP from headers (handles proxies).

    Priority:
    1. X-Forwarded-For (first IP in chain)
    2. X-Real-IP
    3. Fallback to unknown

    Args:
        headers: HTTP headers dictionary

    Returns:
        Extracted IP address or "unknown"

    Examples:
        >>> extract_ip_from_headers({"X-Forwarded-For": "192.168.1.1, 10.0.0.1"})
        '192.168.1.1'
        >>> extract_ip_from_headers({"X-Real-IP": "192.168.1.1"})
        '192.168.1.1'
    """
    # Check X-Forwarded-For
    forwarded = headers.get("X-Forwarded-For")
    if forwarded:
        ips = [ip.strip() for ip in forwarded.split(",") if ip.strip()]
        if ips:
            return ips[0]

    # Check X-Real-IP
    real_ip = headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()

    return DEFAULT_IP


def is_private_ip(ip: str) -> bool:
    """
    Check if an IP address is private (RFC 1918, RFC 4193, etc.).

    Args:
        ip: IP address string

    Returns:
        True if IP is private

    Examples:
        >>> is_private_ip("192.168.1.1")
        True
        >>> is_private_ip("8.8.8.8")
        False
    """
    try:
        return ip_address(ip).is_private
    except ValueError:
        return False


def is_valid_ip(ip: str) -> bool:
    """
    Check if an IP address is valid.

    Args:
        ip: IP address string

    Returns:
        True if IP is valid

    Examples:
        >>> is_valid_ip("192.168.1.1")
        True
        >>> is_valid_ip("invalid")
        False
    """
    try:
        ip_address(ip)
        return True
    except ValueError:
        return False


def mask_ip(ip: str) -> str:
    """
    Mask IP address for privacy (last octet for IPv4, last 4 groups for IPv6).

    Args:
        ip: IP address string

    Returns:
        Masked IP address

    Examples:
        >>> mask_ip("192.168.1.100")
        '192.168.1.xxx'
        >>> mask_ip("2001:db8::1234")
        '2001:db8::xxxx'
    """
    if not ip or ip == DEFAULT_IP:
        return DEFAULT_IP

    try:
        addr = ip_address(ip)
        if isinstance(addr, IPv4Address):
            parts = ip.split(".")
            parts[-1] = "xxx"
            return ".".join(parts)
        elif isinstance(addr, IPv6Address):
            # Mask last 4 groups
            parts = ip.split(":")
            if len(parts) > 4:
                parts[-4:] = ["xxxx"] * 4
            else:
                parts[-1] = "xxxx"
            return ":".join(parts)
    except ValueError:
        return ip

    return ip


# ============================================================
# 🔑 API KEY HELPERS
# ============================================================

def validate_api_key(api_key: str) -> bool:
    """
    Validate API key format.

    Expected format: ts_{live|test|dev}_{48 hex characters}

    Args:
        api_key: API key string

    Returns:
        True if API key format is valid

    Examples:
        >>> validate_api_key("ts_live_a1b2c3d4e5f6...")
        True
        >>> validate_api_key("invalid")
        False
    """
    if not api_key:
        return False
    return bool(re.match(API_KEY_PATTERN, api_key))


def mask_api_key(api_key: str) -> str:
    """
    Mask API key for logging/display (show first 8 and last 4 chars).

    Args:
        api_key: API key string

    Returns:
        Masked API key

    Examples:
        >>> mask_api_key("ts_live_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6")
        'ts_live_****...z6'
    """
    if not api_key:
        return ""

    if len(api_key) <= 16:
        return "****"

    prefix = api_key[:8]
    suffix = api_key[-4:]
    return f"{prefix}****...{suffix}"


def get_api_key_environment(api_key: str) -> Optional[str]:
    """
    Extract environment from API key.

    Args:
        api_key: API key string

    Returns:
        Environment: "live", "test", "dev", or None

    Examples:
        >>> get_api_key_environment("ts_live_a1b2c3...")
        'live'
        >>> get_api_key_environment("ts_test_a1b2c3...")
        'test'
    """
    if not api_key:
        return None

    match = re.match(r"^ts_(live|test|dev)_", api_key)
    if match:
        return match.group(1)
    return None


# ============================================================
# 📊 REQUEST DATA EXTRACTION
# ============================================================

def safe_json_parse(data: Union[str, bytes, Dict]) -> Dict[str, Any]:
    """
    Safely parse JSON data.

    Args:
        data: JSON string, bytes, or dict

    Returns:
        Parsed dictionary or empty dict on failure

    Examples:
        >>> safe_json_parse('{"key": "value"}')
        {'key': 'value'}
        >>> safe_json_parse(b'{"key": "value"}')
        {'key': 'value'}
        >>> safe_json_parse({"key": "value"})
        {'key': 'value'}
        >>> safe_json_parse("invalid")
        {}
    """
    if isinstance(data, dict):
        return data

    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="ignore")

    if isinstance(data, str):
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            return {}

    return {}


def truncate_body(body: str, max_size: int = MAX_BODY_PREVIEW_SIZE) -> str:
    """
    Truncate request body for preview.

    Args:
        body: Request body string
        max_size: Maximum size in bytes

    Returns:
        Truncated body string

    Examples:
        >>> truncate_body("a" * 2000)
        'a' * 1024 + '... (truncated, 2000 bytes)'
    """
    if not body:
        return ""

    body_len = len(body)
    if body_len <= max_size:
        return body

    return f"{body[:max_size]}... (truncated, {body_len} bytes)"


def redact_sensitive_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """
    Redact sensitive headers for logging.

    Args:
        headers: HTTP headers dictionary

    Returns:
        Headers with sensitive values redacted

    Examples:
        >>> redact_sensitive_headers({
        ...     "Authorization": "Bearer secret",
        ...     "Cookie": "session=123",
        ...     "Content-Type": "application/json"
        ... })
        {'Authorization': '[REDACTED]', 'Cookie': '[REDACTED]', 'Content-Type': 'application/json'}
    """
    result = {}
    for key, value in headers.items():
        if key.lower() in SENSITIVE_HEADERS:
            result[key] = "[REDACTED]"
        else:
            result[key] = value
    return result


# ============================================================
# ⏱️ TIMESTAMP HELPERS
# ============================================================

def get_utc_timestamp() -> datetime:
    """
    Get current UTC timestamp with timezone.

    Returns:
        Current UTC datetime

    Examples:
        >>> get_utc_timestamp()
        datetime.datetime(2024, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
    """
    return datetime.now(timezone.utc)


def format_timestamp_iso(timestamp: Optional[datetime] = None) -> str:
    """
    Format timestamp as ISO 8601 string.

    Args:
        timestamp: Datetime object (defaults to current UTC)

    Returns:
        ISO 8601 formatted string

    Examples:
        >>> format_timestamp_iso()
        '2024-01-01T12:00:00+00:00'
    """
    if timestamp is None:
        timestamp = get_utc_timestamp()
    return timestamp.isoformat()


def parse_timestamp_iso(timestamp_str: str) -> Optional[datetime]:
    """
    Parse ISO 8601 timestamp string.

    Args:
        timestamp_str: ISO 8601 formatted string

    Returns:
        Parsed datetime or None on failure

    Examples:
        >>> parse_timestamp_iso("2024-01-01T12:00:00+00:00")
        datetime.datetime(2024, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
    """
    try:
        return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


# ============================================================
# 🏷️ STRING HELPERS
# ============================================================

def truncate_string(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """
    Truncate a string to maximum length.

    Args:
        text: String to truncate
        max_length: Maximum length
        suffix: Suffix to add when truncated

    Returns:
        Truncated string

    Examples:
        >>> truncate_string("This is a very long string", 10)
        'This is...'
    """
    if not text:
        return ""

    if len(text) <= max_length:
        return text

    return text[:max_length - len(suffix)] + suffix


def safe_get(data: Dict[str, Any], key: str, default: Any = None) -> Any:
    """
    Safely get value from dictionary with dot notation support.

    Args:
        data: Dictionary
        key: Key or dot-separated path (e.g., "user.id")
        default: Default value if key not found

    Returns:
        Value or default

    Examples:
        >>> safe_get({"user": {"id": 123}}, "user.id")
        123
        >>> safe_get({"user": {"id": 123}}, "user.email", "unknown")
        'unknown'
    """
    if not data or not key:
        return default

    parts = key.split(".")
    current = data

    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return default

    return current


# ============================================================
# 🔄 RETRY HELPERS
# ============================================================

def is_retryable_status_code(status_code: int) -> bool:
    """
    Check if a status code is retryable.

    Args:
        status_code: HTTP status code

    Returns:
        True if the status code indicates a retryable error

    Examples:
        >>> is_retryable_status_code(500)
        True
        >>> is_retryable_status_code(200)
        False
    """
    return status_code in RETRYABLE_STATUS_CODES


def is_retryable_exception(exception: Exception) -> bool:
    """
    Check if an exception is retryable.

    Args:
        exception: The exception to check

    Returns:
        True if the exception indicates a retryable error

    Examples:
        >>> is_retryable_exception(TimeoutError())
        True
        >>> is_retryable_exception(ValueError())
        False
    """
    exception_name = exception.__class__.__name__
    return exception_name in RETRYABLE_EXCEPTIONS


def calculate_backoff(attempt: int, base_delay: float = 1.0) -> float:
    """
    Calculate exponential backoff delay.

    Args:
        attempt: Current attempt number (0-indexed)
        base_delay: Base delay in seconds

    Returns:
        Delay in seconds

    Examples:
        >>> calculate_backoff(0)
        1.0
        >>> calculate_backoff(1)
        2.0
        >>> calculate_backoff(2)
        4.0
    """
    return base_delay * (2 ** attempt)


# ============================================================
# 🧪 URL HELPERS
# ============================================================

def normalize_url(url: str) -> str:
    """
    Normalize URL (remove trailing slash, ensure protocol).

    Args:
        url: URL string

    Returns:
        Normalized URL

    Examples:
        >>> normalize_url("https://api.triansec.com/")
        'https://api.triansec.com'
        >>> normalize_url("api.triansec.com")
        'https://api.triansec.com'
    """
    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    return url.rstrip("/")


def join_url(base: str, path: str) -> str:
    """
    Join base URL and path.

    Args:
        base: Base URL
        path: Path to append

    Returns:
        Joined URL

    Examples:
        >>> join_url("https://api.triansec.com", "/v1/analyze")
        'https://api.triansec.com/v1/analyze'
        >>> join_url("https://api.triansec.com/", "/v1/analyze")
        'https://api.triansec.com/v1/analyze'
    """
    base = normalize_url(base)
    path = path.lstrip("/")
    return f"{base}/{path}"


# ============================================================
# 📦 DICT HELPERS
# ============================================================

def merge_dicts(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deep merge two dictionaries (override takes precedence).

    Args:
        base: Base dictionary
        override: Override dictionary

    Returns:
        Merged dictionary

    Examples:
        >>> merge_dicts({"a": 1, "b": {"c": 2}}, {"b": {"d": 3}})
        {'a': 1, 'b': {'c': 2, 'd': 3}}
    """
    result = base.copy()

    for key, value in override.items():
        if (
            key in result
            and isinstance(result[key], dict)
            and isinstance(value, dict)
        ):
            result[key] = merge_dicts(result[key], value)
        else:
            result[key] = value

    return result


def filter_none_values(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Filter out keys with None values.

    Args:
        data: Dictionary

    Returns:
        Dictionary without None values

    Examples:
        >>> filter_none_values({"a": 1, "b": None, "c": "test"})
        {'a': 1, 'c': 'test'}
    """
    return {k: v for k, v in data.items() if v is not None}


# ============================================================
# 🔍 VALIDATION HELPERS
# ============================================================

def is_valid_uuid(uuid_str: str) -> bool:
    """
    Check if string is a valid UUID.

    Args:
        uuid_str: UUID string

    Returns:
        True if valid UUID

    Examples:
        >>> is_valid_uuid("123e4567-e89b-12d3-a456-426614174000")
        True
        >>> is_valid_uuid("invalid")
        False
    """
    import uuid

    try:
        uuid.UUID(uuid_str)
        return True
    except ValueError:
        return False


def is_valid_hex(hex_str: str) -> bool:
    """
    Check if string is valid hexadecimal.

    Args:
        hex_str: Hex string

    Returns:
        True if valid hex

    Examples:
        >>> is_valid_hex("a1b2c3")
        True
        >>> is_valid_hex("invalid")
        False
    """
    if not hex_str:
        return False
    try:
        int(hex_str, 16)
        return True
    except ValueError:
        return False


def sanitize_input(text: str, max_length: int = 1000) -> str:
    """
    Sanitize input string (strip control characters, limit length).

    Args:
        text: Input text
        max_length: Maximum length

    Returns:
        Sanitized text

    Examples:
        >>> sanitize_input("Hello\\nWorld\\t!")
        'HelloWorld!'
        >>> sanitize_input("a" * 2000)
        'a' * 1000
    """
    if not text:
        return ""

    # Remove control characters
    sanitized = re.sub(r"[\x00-\x1f\x7f]", "", text)

    # Truncate
    return sanitized[:max_length]


# ============================================================
# 🧪 TESTING HELPERS
# ============================================================

def create_mock_request_data(
    ip: str = "192.168.1.1",
    user_agent: str = "Mozilla/5.0",
    endpoint: str = "/api/test",
    method: str = "GET",
    **kwargs
) -> Dict[str, Any]:
    """
    Create mock request data for testing.

    Args:
        ip: IP address
        user_agent: User-Agent header
        endpoint: Request endpoint
        method: HTTP method
        **kwargs: Additional fields

    Returns:
        Mock request data dictionary

    Examples:
        >>> create_mock_request_data()
        {
            'ip_address': '192.168.1.1',
            'user_agent': 'Mozilla/5.0',
            'endpoint': '/api/test',
            'method': 'GET',
            'fingerprint': '...',
            'timestamp': '2024-...'
        }
    """
    data = {
        "ip_address": ip,
        "user_agent": user_agent,
        "endpoint": endpoint,
        "method": method,
        "fingerprint": generate_fingerprint(ip, user_agent),
        "timestamp": format_timestamp_iso(),
        "headers": {},
        "query_params": {},
        "body_preview": None,
        "user_id": None,
    }

    # Merge with kwargs
    data.update(kwargs)
    return filter_none_values(data)


# ============================================================
# 📋 EXPORTS
# ============================================================

__all__ = [
    # Block duration helpers
    "validate_block_duration",
    "is_valid_block_duration",
    "get_block_duration_hours",
    "get_block_duration_seconds",
    "get_block_duration_description",

    # Fingerprint generation
    "generate_fingerprint",
    "generate_behavioral_fingerprint",

    # IP address helpers
    "extract_ip_from_headers",
    "is_private_ip",
    "is_valid_ip",
    "mask_ip",

    # API key helpers
    "validate_api_key",
    "mask_api_key",
    "get_api_key_environment",

    # Request data extraction
    "safe_json_parse",
    "truncate_body",
    "redact_sensitive_headers",

    # Timestamp helpers
    "get_utc_timestamp",
    "format_timestamp_iso",
    "parse_timestamp_iso",

    # String helpers
    "truncate_string",
    "safe_get",

    # Retry helpers
    "is_retryable_status_code",
    "is_retryable_exception",
    "calculate_backoff",

    # URL helpers
    "normalize_url",
    "join_url",

    # Dict helpers
    "merge_dicts",
    "filter_none_values",

    # Validation helpers
    "is_valid_uuid",
    "is_valid_hex",
    "sanitize_input",

    # Testing helpers
    "create_mock_request_data",
]