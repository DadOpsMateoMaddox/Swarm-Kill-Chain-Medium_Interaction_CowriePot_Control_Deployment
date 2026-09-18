"""Minimal urllib GET helper shared by every provider.

Provider base URLs are always module-level constants passed in by the
caller -- never constructed from attacker-observed input -- so there is no
path by which a Cowrie event can choose a hostname or scheme.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, Optional, Tuple

from .provider_result import (
    STATUS_ERROR,
    STATUS_MALFORMED,
    STATUS_NOT_FOUND,
    STATUS_OK,
    STATUS_RATE_LIMITED,
    STATUS_TIMEOUT,
    STATUS_UNAUTHORIZED,
)


def get_json(
    url: str,
    headers: Dict[str, str],
    timeout: float,
) -> Tuple[str, Optional[int], Optional[dict], Optional[bytes], Optional[float]]:
    """Perform one GET and classify the outcome.

    Returns (status, http_status, parsed_json_or_None, raw_body_or_None,
    retry_after_seconds_or_None). retry_after is only ever non-None on a 429.
    Never raises for expected HTTP/network failure modes -- those become a
    status string so callers can fail open.
    """
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read()
            http_status = response.status
    except urllib.error.HTTPError as exc:
        body = exc.read() if exc.fp else b""
        http_status = exc.code
        if http_status == 404:
            return STATUS_NOT_FOUND, http_status, _try_json(body), body, None
        if http_status in (401, 403):
            return STATUS_UNAUTHORIZED, http_status, None, body, None
        if http_status == 429:
            return STATUS_RATE_LIMITED, http_status, None, body, _retry_after(exc, body)
        return STATUS_ERROR, http_status, None, body, None
    except (urllib.error.URLError, TimeoutError, OSError):
        return STATUS_TIMEOUT, None, None, None, None

    parsed = _try_json(body)
    if parsed is None:
        return STATUS_MALFORMED, http_status, None, body, None
    return STATUS_OK, http_status, parsed, body, None


def _retry_after(exc: urllib.error.HTTPError, body: bytes) -> Optional[float]:
    header = exc.headers.get("Retry-After") if exc.headers is not None else None
    if header is not None:
        try:
            return float(header)
        except ValueError:
            pass
    parsed = _try_json(body)
    if isinstance(parsed, dict):
        value = parsed.get("retry_after")
        if isinstance(value, (int, float)):
            return float(value)
    return None


def _try_json(body: bytes) -> Optional[dict]:
    if not body:
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def build_query(base_url: str, params: Dict[str, str]) -> str:
    return f"{base_url}?{urllib.parse.urlencode(params)}"
