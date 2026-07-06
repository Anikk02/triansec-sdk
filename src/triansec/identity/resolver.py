"""
Identity extraction for TrianSec SDK.

This module extracts raw request data from incoming requests.
It does NOT generate fingerprints or resolve identities - 
that happens on the security engine server.

The SDK extracts:
- IP address
- User-Agent
- Request path and method
- Headers (including API key)
- Cookies (including identity_id from X-TrianSec-User-ID)
- Query parameters

The server uses these to resolve identity and set cookies when needed.
"""

import logging
from datetime import datetime
from typing import Optional, Dict, Any
from fastapi import Request

from triansec.constants import (
    DEFAULT_IP,
    DEFAULT_USER_AGENT,
    HEADER_X_FORWARDED_FOR,
    HEADER_USER_AGENT,
    HEADER_API_KEY,
    COOKIE_USER_ID,
)
from triansec.logger import get_logger

logger = get_logger(__name__)


# ============================================================
# 🔍 EXTRACT REQUEST DATA
# ============================================================

def extract_request_data(request: Request) -> Dict[str, Any]:
    """
    Extract raw request data for forwarding to the security engine.
    
    This function extracts the identity_id from the X-TrianSec-User-ID cookie
    and forwards it to the server. The server uses this to resolve identity.
    
    IMPORTANT:
    - SDK does NOT generate identity_id - server does
    - SDK does NOT set cookies - server does
    - SDK just extracts and forwards the cookie value
    
    Args:
        request: FastAPI Request object
    
    Returns:
        Dictionary with raw request data including identity_id from cookie
    
    Examples:
        >>> data = extract_request_data(request)
        >>> data["identity_id"]  # From cookie
        'api:123:user:456e7-e89b-12d3-a456-426614174000'
    """
    logger.debug(f"Extracting request data from {request.method} {request.url.path}")
    
    # ── 1. Extract IP ──────────────────────────────────────────────────────
    ip = _extract_ip(request)
    
    # ── 2. Extract User-Agent ─────────────────────────────────────────────
    user_agent = _extract_user_agent(request)
    
    # ── 3. Extract API Key (for server to validate) ───────────────────────
    api_key = _extract_api_key(request)
    
    # ── 4. Extract Identity ID from Cookie ────────────────────────────────
    identity_id = _extract_identity_id_from_cookie(request)
    
    # ── 5. Extract Path and Method ────────────────────────────────────────
    endpoint = request.url.path
    method = request.method
    
    # ── 6. Extract Headers ─────────────────────────────────────────────────
    headers = _extract_headers(request)
    
    # ── 7. Extract Cookies ─────────────────────────────────────────────────
    cookies = _extract_cookies(request)
    
    # ── 8. Extract Query Params ────────────────────────────────────────────
    query_params = _extract_query_params(request)
    
    # ── 9. Extract Body Preview (optional) ────────────────────────────────
    body_preview = _extract_body_preview(request)
    
    # Build result
    result = {
        "ip_address": ip,
        "user_agent": user_agent,
        "endpoint": endpoint,
        "method": method,
        "api_key": api_key,              # Server validates this
        "identity_id": identity_id,      # Server uses this to resolve identity
        "headers": headers,
        "cookies": cookies,
        "query_params": query_params,
        "timestamp": datetime.utcnow().isoformat(),
    }
    
    if body_preview:
        result["body_preview"] = body_preview
    
    logger.debug(
        f"Request data extracted: ip={ip}, "
        f"endpoint={endpoint}, "
        f"method={method}, "
        f"has_api_key={bool(api_key)}, "
        f"has_identity_id={bool(identity_id)}"
    )
    
    return result


# ============================================================
# 🔧 EXTRACTION HELPERS
# ============================================================

def _extract_ip(request: Request) -> str:
    """
    Extract client IP address from request.
    
    Supports:
    - X-Forwarded-For (proxy chains)
    - X-Real-IP
    - Direct client host
    
    Args:
        request: FastAPI Request object
    
    Returns:
        Client IP address or "unknown"
    """
    # Check X-Forwarded-For (first IP in chain)
    forwarded = request.headers.get(HEADER_X_FORWARDED_FOR)
    if forwarded:
        ips = [ip.strip() for ip in forwarded.split(",") if ip.strip()]
        if ips:
            return ips[0]
    
    # Check X-Real-IP
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    
    # Fallback to direct client host
    if request.client and request.client.host:
        return request.client.host
    
    return DEFAULT_IP


def _extract_user_agent(request: Request) -> str:
    """Extract User-Agent from request."""
    return request.headers.get(HEADER_USER_AGENT, DEFAULT_USER_AGENT)


def _extract_api_key(request: Request) -> Optional[str]:
    """
    Extract API key from request headers.
    
    Priority:
    1. X-API-Key header
    2. Authorization: Bearer <token> (if it's an API key)
    
    Server validates this key against the database.
    """
    # Check X-API-Key header
    api_key = request.headers.get(HEADER_API_KEY)
    if api_key:
        return api_key.strip()
    
    # Check Authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1].strip()
        if token.startswith("ts_"):
            return token
    
    return None


def _extract_identity_id_from_cookie(request: Request) -> Optional[str]:
    """
    Extract identity_id from X-TrianSec-User-ID cookie.
    
    This cookie is SET by the SECURITY ENGINE (server) and READ by the SDK.
    The cookie value is the identity_id generated by the server.
    
    Identity ID format: api:{client_id}:user:{user_identifier}
    Example: api:123:user:456e7-e89b-12d3-a456-426614174000
    
    Args:
        request: FastAPI Request object
    
    Returns:
        Identity ID from cookie or None
    
    Examples:
        >>> request.cookies["X-TrianSec-User-ID"] = "api:123:user:456e7"
        >>> _extract_identity_id_from_cookie(request)
        'api:123:user:456e7'
    """
    return request.cookies.get(COOKIE_USER_ID)


def _extract_headers(request: Request) -> Dict[str, str]:
    """
    Extract relevant headers from request.
    
    Excludes sensitive headers (authorization, api-key, cookie).
    """
    exclude = [
        "authorization",
        "x-api-key",
        "cookie",
        "set-cookie",
    ]
    
    headers = {}
    for key, value in request.headers.items():
        if key.lower() not in exclude:
            headers[key] = value
    
    return headers


def _extract_cookies(request: Request) -> Dict[str, str]:
    """Extract cookies from request."""
    return dict(request.cookies)


def _extract_query_params(request: Request) -> Dict[str, str]:
    """Extract query parameters from request."""
    return dict(request.query_params)


def _extract_body_preview(request: Request) -> Optional[str]:
    """
    Extract a preview of the request body.
    
    Only for logging/debugging, not for analysis.
    """
    try:
        if hasattr(request, "_body"):
            body = request._body
            if body:
                import json
                try:
                    data = json.loads(body)
                    return json.dumps(data)[:500]
                except Exception:
                    return str(body)[:500]
    except Exception:
        pass
    
    return None


# ============================================================
# 📋 EXPORTS
# ============================================================

__all__ = [
    "extract_request_data",
]