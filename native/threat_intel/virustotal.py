"""VirusTotal: IP reputation/detection context, and hash-only file lookup.

File lookups are read-only by construction: this module has no upload
function at all, so there is no code path that could submit a captured
sample to VirusTotal, accidentally or otherwise.
"""

from __future__ import annotations

from typing import Any, Dict

from .http_client import get_json
from .provider_result import (
    STATUS_MISSING_CREDENTIAL,
    STATUS_OK,
    ProviderResponse,
)

API_VERSION = "v3"
IP_BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses"
FILE_BASE_URL = "https://www.virustotal.com/api/v3/files"


def lookup_ip(ip: str, api_key: str, timeout: float) -> ProviderResponse:
    if not api_key:
        return ProviderResponse(status=STATUS_MISSING_CREDENTIAL)
    url = f"{IP_BASE_URL}/{ip}"
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    status, http_status, parsed, raw_body, retry_after = get_json(url, headers, timeout)
    if status != STATUS_OK or parsed is None:
        return ProviderResponse(status=status, http_status=http_status, raw_body=raw_body, retry_after_seconds=retry_after)
    return ProviderResponse(
        status=STATUS_OK,
        http_status=http_status,
        normalized=_normalize_ip(parsed),
        raw_body=raw_body,
    )


def lookup_file_hash(sha256: str, api_key: str, timeout: float) -> ProviderResponse:
    """Read-only hash lookup. Never uploads or resubmits a sample."""
    if not api_key:
        return ProviderResponse(status=STATUS_MISSING_CREDENTIAL)
    url = f"{FILE_BASE_URL}/{sha256}"
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    status, http_status, parsed, raw_body, retry_after = get_json(url, headers, timeout)
    if status != STATUS_OK or parsed is None:
        return ProviderResponse(status=status, http_status=http_status, raw_body=raw_body, retry_after_seconds=retry_after)
    return ProviderResponse(
        status=STATUS_OK,
        http_status=http_status,
        normalized=_normalize_file(parsed),
        raw_body=raw_body,
    )


def _normalize_ip(payload: Dict[str, Any]) -> Dict[str, Any]:
    attributes = (payload.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    return {
        "reputation": attributes.get("reputation"),
        "country": attributes.get("country"),
        "asn": attributes.get("asn"),
        "as_owner": attributes.get("as_owner"),
        "last_analysis_stats": {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        },
    }


def _normalize_file(payload: Dict[str, Any]) -> Dict[str, Any]:
    attributes = (payload.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    return {
        "sha256": attributes.get("sha256"),
        "type_description": attributes.get("type_description"),
        "last_analysis_stats": {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        },
    }
