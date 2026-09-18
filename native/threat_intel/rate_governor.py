"""Provider-global request governance.

Per-observable negative caching (cache.py) alone does not stop a burst of
distinct IPs from each independently hitting a provider that has started
returning 429s -- each new IP is a cache miss, so each one would still fire a
network request. This governor sits in front of that: once a provider has
told us to back off, no further network calls to that provider happen at
all, for any observable, until the cooldown expires -- regardless of how
many distinct IPs are queued behind it.
"""

from __future__ import annotations

import threading
import time
from typing import Callable, Optional

DEFAULT_MIN_INTERVAL_SECONDS = 0.2
DEFAULT_COOLDOWN_SECONDS = 30.0
MAX_COOLDOWN_SECONDS = 600.0


class ProviderRateGovernor:
    """Thread-safe: the broker calls this from multiple worker threads."""

    def __init__(
        self,
        min_interval_seconds: float = DEFAULT_MIN_INTERVAL_SECONDS,
        default_cooldown_seconds: float = DEFAULT_COOLDOWN_SECONDS,
        max_cooldown_seconds: float = MAX_COOLDOWN_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._min_interval = min_interval_seconds
        self._default_cooldown = default_cooldown_seconds
        self._max_cooldown = max_cooldown_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._next_allowed_at = 0.0
        self._cooldown_until = 0.0
        self._consecutive_unretriable_rate_limits = 0

    def can_call(self) -> bool:
        with self._lock:
            now = self._clock()
            return now >= self._cooldown_until and now >= self._next_allowed_at

    def note_call_attempt(self) -> None:
        with self._lock:
            self._next_allowed_at = self._clock() + self._min_interval

    def note_success(self) -> None:
        with self._lock:
            self._consecutive_unretriable_rate_limits = 0

    def note_rate_limited(self, retry_after_seconds: Optional[float] = None) -> None:
        with self._lock:
            if retry_after_seconds is not None:
                backoff = min(max(retry_after_seconds, 1.0), self._max_cooldown)
                self._consecutive_unretriable_rate_limits = 0
            else:
                # No Retry-After given: back off exponentially so repeated
                # unannounced rate-limiting doesn't settle into a tight loop
                # of default-cooldown-length probes.
                self._consecutive_unretriable_rate_limits += 1
                backoff = min(
                    self._default_cooldown * (2 ** (self._consecutive_unretriable_rate_limits - 1)),
                    self._max_cooldown,
                )
            self._cooldown_until = self._clock() + backoff
