"""Shodan: external host exposure / infrastructure posture.

Host data changes slowly relative to Cowrie telemetry, so this is queried at
most once per cache TTL per IP -- never per event.
"""

from __future__ import annotations

from typing import Any, Dict

from .http_client import build_query, get_json
from .provider_result import (
    STATUS_MISSING_CREDENTIAL,
    STATUS_OK,
    ProviderResponse,
)

API_VERSION = "v1"
BASE_URL = "https://api.shodan.io/shodan/host"


def lookup_ip(ip: str, api_key: str, timeout: float) -> ProviderResponse:
    if not api_key:
        return ProviderResponse(status=STATUS_MISSING_CREDENTIAL)
    url = build_query(f"{BASE_URL}/{ip}", {"key": api_key})
    status, http_status, parsed, raw_body, retry_after = get_json(url, {"Accept": "application/json"}, timeout)
    if status != STATUS_OK or parsed is None:
        return ProviderResponse(status=status, http_status=http_status, raw_body=raw_body, retry_after_seconds=retry_after)
    return ProviderResponse(
        status=STATUS_OK,
        http_status=http_status,
        normalized=_normalize(parsed),
        raw_body=raw_body,
    )


def _normalize(payload: Dict[str, Any]) -> Dict[str, Any]:
    services = payload.get("data") or []
    products = sorted({entry["product"] for entry in services if entry.get("product")})
    transports = sorted({entry["transport"] for entry in services if entry.get("transport")})
    return {
        "org": payload.get("org"),
        "isp": payload.get("isp"),
        "asn": payload.get("asn"),
        "country": payload.get("country_name"),
        "hostnames": payload.get("hostnames") or [],
        "domains": payload.get("domains") or [],
        "ports": sorted(payload.get("ports") or []),
        "products": products,
        "transport": transports,
        "last_update": payload.get("last_update"),
        "vulns": sorted(payload.get("vulns") or []),
        "tags": payload.get("tags") or [],
    }
