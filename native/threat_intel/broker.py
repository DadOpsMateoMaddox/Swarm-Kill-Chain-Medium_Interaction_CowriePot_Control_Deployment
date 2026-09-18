"""Orchestrates GreyNoise / VirusTotal / Shodan lookups for one IP.

Fail-open by construction: any provider exception, timeout, or missing
credential yields a status envelope for that provider alone. It never raises
out of `enrich_ip`, so a broken/rate-limited/misconfigured provider can never
block Cowrie telemetry or the Discord alert path.

Enrichment happens once per IP per cache TTL (Design Requirement 8), not once
per Cowrie event -- callers are expected to key their own "have I already
enriched this IP recently" decision off the session-cluster layer, and this
broker's cache is the second, provider-level line of defense against
redundant queries.
"""

from __future__ import annotations

import hashlib
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from . import greynoise, observables, shodan, virustotal
from .cache import EnrichmentCache, cache_key
from .parameter_store import ParameterRegistry
from .rate_governor import ProviderRateGovernor
from .provider_result import (
    STATUS_INVALID_OBSERVABLE,
    STATUS_MISSING_CREDENTIAL,
    STATUS_NOT_FOUND,
    STATUS_OK,
    STATUS_RATE_LIMITED,
    STATUS_UNAVAILABLE,
    ProviderResponse,
)

DEFAULT_TIMEOUT_SECONDS = 5.0
ERROR_CACHE_TTL_SECONDS = 300.0

DEFAULT_TTL_SECONDS = {
    "greynoise": 45 * 60,
    "virustotal": 3 * 60 * 60,
    "shodan": 18 * 60 * 60,
}

_PROVIDER_MODULES = {
    "greynoise": greynoise,
    "virustotal": virustotal,
    "shodan": shodan,
}

_LOG_EVENT_BY_STATUS = {
    STATUS_OK: "enrichment_success",
    STATUS_NOT_FOUND: "enrichment_not_found",
    STATUS_RATE_LIMITED: "enrichment_rate_limited",
    "timeout": "enrichment_timeout",
    "error": "enrichment_error",
    "malformed": "enrichment_error",
    "unauthorized": "enrichment_error",
    STATUS_MISSING_CREDENTIAL: "enrichment_error",
}


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _observable_hash(observable: str) -> str:
    return hashlib.sha256(observable.encode("utf-8")).hexdigest()[:16]


class ThreatIntelBroker:
    def __init__(
        self,
        parameter_registry: ParameterRegistry,
        cache: EnrichmentCache,
        logger: logging.Logger,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        ttl_seconds: Optional[Dict[str, float]] = None,
        rate_governor_clock: Optional[Any] = None,
    ) -> None:
        self._parameters = parameter_registry
        self._cache = cache
        self._logger = logger
        self._timeout = timeout_seconds
        self._ttl = dict(DEFAULT_TTL_SECONDS)
        if ttl_seconds:
            self._ttl.update(ttl_seconds)
        # Provider-global: shared across every observable, not per-IP. Once
        # a provider 429s, every other in-flight or future lookup for that
        # provider is skipped -- no network call at all -- until its
        # cooldown expires, regardless of how many distinct IPs are queued.
        governor_kwargs = {"clock": rate_governor_clock} if rate_governor_clock is not None else {}
        self._rate_governors = {name: ProviderRateGovernor(**governor_kwargs) for name in _PROVIDER_MODULES}

    def enrich_ip(self, ip_str: str) -> Dict[str, Dict[str, Any]]:
        address = observables.parse_public_ip(ip_str)
        if address is None:
            return {
                name: self._envelope(name, "ip", ip_str, STATUS_INVALID_OBSERVABLE, cache_hit=False)
                for name in _PROVIDER_MODULES
            }
        observable = str(address)
        results: Dict[str, Dict[str, Any]] = {}
        with ThreadPoolExecutor(max_workers=len(_PROVIDER_MODULES)) as pool:
            futures = {
                pool.submit(self._lookup_one, name, observable): name
                for name in _PROVIDER_MODULES
            }
            for future, name in futures.items():
                try:
                    results[name] = future.result(timeout=self._timeout + 2.0)
                except Exception:  # noqa: BLE001 - fail-open is the whole point
                    self._logger.warning("enrichment_error provider=%s ip_hash=%s", name, _observable_hash(observable))
                    results[name] = self._envelope(name, "ip", observable, STATUS_UNAVAILABLE, cache_hit=False)
        return results

    def _lookup_one(self, provider: str, observable: str) -> Dict[str, Any]:
        key = cache_key(provider, "ip", observable)
        cached = self._cache.get(key)
        if cached is not None:
            self._logger.info("enrichment_cache_hit provider=%s ip_hash=%s", provider, _observable_hash(observable))
            envelope = dict(cached)
            envelope["cache_hit"] = True
            envelope.pop("expires_at_epoch", None)
            return envelope

        self._logger.info("enrichment_cache_miss provider=%s ip_hash=%s", provider, _observable_hash(observable))
        api_key = self._parameters.get(provider)
        if not api_key:
            self._logger.warning("enrichment_error provider=%s reason=missing_credential", provider)
            return self._envelope(provider, "ip", observable, STATUS_MISSING_CREDENTIAL, cache_hit=False)

        governor = self._rate_governors[provider]
        if not governor.can_call():
            # Provider-global cooldown active: skip the network call
            # entirely, for this observable and every other one, until it
            # expires. Not cached -- the governor itself is the throttle.
            self._logger.info("enrichment_rate_limited provider=%s ip_hash=%s reason=provider_cooldown", provider, _observable_hash(observable))
            return self._envelope(provider, "ip", observable, STATUS_RATE_LIMITED, cache_hit=False)

        module = _PROVIDER_MODULES[provider]
        governor.note_call_attempt()
        try:
            response = module.lookup_ip(observable, api_key, self._timeout)
        except Exception:  # noqa: BLE001 - a provider bug must not break Discord
            self._logger.warning("enrichment_error provider=%s ip_hash=%s", provider, _observable_hash(observable))
            response = ProviderResponse(status=STATUS_UNAVAILABLE)

        if response.status == STATUS_RATE_LIMITED:
            governor.note_rate_limited(response.retry_after_seconds)
        else:
            governor.note_success()

        event = _LOG_EVENT_BY_STATUS.get(response.status, "enrichment_error")
        self._logger.info("%s provider=%s ip_hash=%s", event, provider, _observable_hash(observable))

        envelope = self._envelope(
            provider,
            "ip",
            observable,
            response.status,
            cache_hit=False,
            http_status=response.http_status,
            normalized=response.normalized,
            raw_body=response.raw_body,
            api_version=getattr(module, "API_VERSION", "unknown"),
        )
        if response.status in (STATUS_OK, STATUS_NOT_FOUND):
            self._cache.set(key, envelope, self._ttl.get(provider, DEFAULT_TTL_SECONDS.get(provider, 3600)))
        elif response.status in (STATUS_RATE_LIMITED, "error", "malformed", "timeout", "unauthorized"):
            self._cache.set(key, envelope, ERROR_CACHE_TTL_SECONDS)
        return envelope

    @staticmethod
    def _envelope(
        provider: str,
        observable_type: str,
        observable: str,
        status: str,
        cache_hit: bool,
        http_status: Optional[int] = None,
        normalized: Optional[Dict[str, Any]] = None,
        raw_body: Optional[bytes] = None,
        api_version: str = "unknown",
    ) -> Dict[str, Any]:
        response_sha256 = hashlib.sha256(raw_body).hexdigest() if raw_body else None
        return {
            "provider": provider,
            "api_version": api_version,
            "observable_type": observable_type,
            "observable": observable,
            "queried_at": _utcnow_iso(),
            "status": status,
            "cache_hit": cache_hit,
            "http_status": http_status,
            "response_sha256": response_sha256,
            "normalized": normalized or {},
        }
