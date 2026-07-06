"""
Identity extraction for TrianSec SDK.

This module extracts raw request data from incoming requests for forwarding
to the security engine server.
"""

from triansec.identity.resolver import extract_request_data

__all__ = [
    "extract_request_data",
]