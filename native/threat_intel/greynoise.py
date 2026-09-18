"""GreyNoise: internet-scanning / behavioral infrastructure context.

Uses the GreyNoise v3 Community lookup -- the lightweight endpoint intended
for exactly this kind of live-alerting use case. The Community tier does not
return `actor`/`tags`; those fields normalize to empty rather than being
omitted, so downstream code has a stable schema regardless of API tier.
"""

from __future__ import annotations

from typing import Any, Dict

from .http_client import get_json
from .provider_result import (
    STATUS_MISSING_CREDENTIAL,
    STATUS_OK,
    ProviderResponse,
)

API_VERSION = "v3-community"
BASE_URL = "https://api.greynoise.io/v3/community"


def lookup_ip(ip: str, api_key: str, timeout: float) -> ProviderResponse:
    if not api_key:
        return ProviderResponse(status=STATUS_MISSING_CREDENTIAL)
    url = f"{BASE_URL}/{ip}"
    headers = {"key": api_key, "Accept": "application/json"}
    status, http_status, parsed, raw_body, retry_after = get_json(url, headers, timeout)
    if status != STATUS_OK or parsed is None:
        return ProviderResponse(status=status, http_status=http_status, raw_body=raw_body, retry_after_seconds=retry_after)
    return ProviderResponse(
        status=STATUS_OK,
        http_status=http_status,
        normalized=_normalize(parsed),
        raw_body=raw_body,
    )


def _normalize(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "classification": payload.get("classification"),
        "noise": bool(payload.get("noise", False)),
        "riot": bool(payload.get("riot", False)),
        "actor": payload.get("actor"),
        "tags": payload.get("tags") or [],
        "name": payload.get("name"),
        "last_seen": payload.get("last_seen"),
        "link": payload.get("link"),
    }
