"""
Security models for TrianSec SDK.

These models are used for request/response communication with the
TrianSec security engine at runtime.
"""

from typing import List, Optional, Literal, Dict, Any

from pydantic import BaseModel, Field


class RequestData(BaseModel):
    """
    Request data sent to the security engine.
    
    This contains all the metadata extracted from the incoming request
    that the security engine needs for analysis.
    """
    
    ip_address: str = Field(
        ...,
        description="Client IP address"
    )
    user_agent: str = Field(
        ...,
        description="User-Agent header"
    )
    endpoint: str = Field(
        ...,
        description="Request path"
    )
    method: str = Field(
        ...,
        description="HTTP method"
    )
    timestamp: Optional[str] = Field(
        None,
        description="Request timestamp (ISO format)"
    )
    fingerprint: Optional[str] = Field(
        None,
        description="Identity fingerprint"
    )
    api_key: Optional[str] = Field(
        None,
        description="API key from headers"
    )
    identity_id: Optional[str] = Field(
        None,
        description="Identity ID from cookie"
    )
    headers: Optional[Dict[str, str]] = Field(
        None,
        description="Request headers"
    )
    cookies: Optional[Dict[str, str]] = Field(
        None,
        description="Request cookies"
    )
    query_params: Optional[Dict[str, str]] = Field(
        None,
        description="Query parameters"
    )
    body_preview: Optional[str] = Field(
        None,
        description="Preview of request body (for debugging)"
    )


class SecurityDecision(BaseModel):
    """
    Security decision from the security engine.
    
    The SDK only receives the ACTION and supporting information.
    All internal scores (trust, risk, suspicion) stay on the server.
    """
    
    action: Literal["allow", "block", "throttle"] = Field(
        ...,
        description="Security action to take"
    )
    reason: List[str] = Field(
        default_factory=list,
        description="Human-readable reasons for the decision"
    )
    request_uuid: str = Field(
        ...,
        description="Request UUID for tracing"
    )
    block_duration: Optional[int] = Field(
        None,
        description="Block duration in seconds (if action is 'block')"
    )
    retry_after: Optional[int] = Field(
        None,
        description="Retry-After seconds (if action is 'throttle')"
    )


# ============================================================
# 📋 EXPORTS
# ============================================================

__all__ = [
    "RequestData",
    "SecurityDecision",
]