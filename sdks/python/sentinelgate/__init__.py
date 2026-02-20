"""SentinelGate Python SDK - Policy Decision API client."""

__version__ = "0.1.0"

from .client import SentinelGateClient
from .exceptions import (
    ApprovalTimeoutError,
    PolicyDeniedError,
    SentinelGateError,
    ServerUnreachableError,
)

__all__ = [
    "SentinelGateClient",
    "SentinelGateError",
    "PolicyDeniedError",
    "ApprovalTimeoutError",
    "ServerUnreachableError",
]
