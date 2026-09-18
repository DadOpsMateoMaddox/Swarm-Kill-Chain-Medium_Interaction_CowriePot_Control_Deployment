"""Outbound Discord rate governor.

Targets roughly one webhook POST per second and, on a 429, stops sending
entirely for a cooldown window instead of retrying immediately. This turns a
burst into aggregation, not data loss: queued items stay queued (the caller
is responsible for not dead-lettering on a governor-blocked send), and a
single recovery message is emitted once sending resumes rather than replaying
every suppressed item individually.
"""

from __future__ import annotations

import time
from typing import Callable, Optional

DEFAULT_MIN_INTERVAL_SECONDS = 1.0
DEFAULT_COOLDOWN_SECONDS = 30.0
MAX_COOLDOWN_SECONDS = 300.0


class DiscordRateGovernor:
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
        self._next_allowed_at = 0.0
        self._cooldown_until = 0.0
        self._degraded = False
        self._suppressed_during_degraded = 0

    @property
    def degraded(self) -> bool:
        return self._degraded

    def can_send(self) -> bool:
        now = self._clock()
        return now >= self._cooldown_until and now >= self._next_allowed_at

    def note_send_attempt(self) -> None:
        self._next_allowed_at = self._clock() + self._min_interval

    def note_blocked(self, queue_depth: int) -> None:
        """Call when a send was skipped because can_send() was False.

        Tracks the largest backlog observed while degraded as the reported
        suppressed count -- a defensible proxy for "how many summaries piled
        up", without needing to count individual skipped send attempts.
        """
        if self._degraded:
            self._suppressed_during_degraded = max(self._suppressed_during_degraded, queue_depth)

    def note_success(self):
        """Returns (just_recovered: bool, suppressed_count: int)."""
        if self._degraded:
            self._degraded = False
            suppressed = self._suppressed_during_degraded
            self._suppressed_during_degraded = 0
            return True, suppressed
        return False, 0

    def note_rate_limited(self, retry_after_seconds: Optional[float] = None) -> bool:
        """Enter/extend degraded mode. Returns True if this newly entered degraded mode."""
        backoff = self._default_cooldown if retry_after_seconds is None else retry_after_seconds
        backoff = min(max(backoff, 1.0), self._max_cooldown)
        self._cooldown_until = self._clock() + backoff
        newly_degraded = not self._degraded
        self._degraded = True
        return newly_degraded
