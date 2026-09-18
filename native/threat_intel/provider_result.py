"""Shared result shape every provider module returns to the broker.

Keeping this uniform means the broker builds the full provenance envelope
(Design Requirement 10) exactly once, instead of each provider duplicating
that bookkeeping.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

# Every possible outcome a provider lookup can report. "ok" and "not_found"
# are the only statuses carrying meaningful `normalized` data.
STATUS_OK = "ok"
STATUS_NOT_FOUND = "not_found"
STATUS_UNAUTHORIZED = "unauthorized"
STATUS_RATE_LIMITED = "rate_limited"
STATUS_ERROR = "error"
STATUS_TIMEOUT = "timeout"
STATUS_MALFORMED = "malformed"
STATUS_MISSING_CREDENTIAL = "missing_credential"
STATUS_INVALID_OBSERVABLE = "invalid_observable"
STATUS_UNAVAILABLE = "unavailable"


@dataclass
class ProviderResponse:
    status: str
    http_status: Optional[int] = None
    normalized: Dict[str, Any] = field(default_factory=dict)
    raw_body: Optional[bytes] = None
    retry_after_seconds: Optional[float] = None
