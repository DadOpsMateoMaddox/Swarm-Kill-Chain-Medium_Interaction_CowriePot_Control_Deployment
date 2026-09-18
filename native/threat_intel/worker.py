"""Bounded background executor for threat-intel enrichment.

Cowrie log consumption (offset tracking) must never wait on a provider.
`try_submit` and `drain_completed` are both non-blocking; the actual
`broker.enrich_ip()` call -- which can take several seconds across three
providers -- always runs on a background thread, off the polling loop.

Backpressure is explicit: once `max_inflight` enrichments are already
running, `try_submit` returns False immediately rather than queuing
unboundedly or blocking. The caller is expected to fail open (build the
summary without enrichment) when that happens.
"""

from __future__ import annotations

import queue
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_MAX_WORKERS = 3
DEFAULT_MAX_INFLIGHT = 64


class ThreatIntelWorker:
    def __init__(
        self,
        broker: Any,
        max_workers: int = DEFAULT_MAX_WORKERS,
        max_inflight: int = DEFAULT_MAX_INFLIGHT,
    ) -> None:
        self._broker = broker
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._max_inflight = max_inflight
        self._lock = threading.Lock()
        self._inflight = 0
        self._results: "queue.Queue[Tuple[Any, Optional[Dict[str, Any]]]]" = queue.Queue()

    def try_submit(self, cluster: Any) -> bool:
        with self._lock:
            if self._inflight >= self._max_inflight:
                return False
            self._inflight += 1

        def _run() -> None:
            try:
                enrichment = self._broker.enrich_ip(cluster.src_ip)
            except Exception:  # noqa: BLE001 - a broker bug must not break Discord or ingestion
                enrichment = None
            finally:
                with self._lock:
                    self._inflight -= 1
            self._results.put((cluster, enrichment))

        self._executor.submit(_run)
        return True

    def drain_completed(self) -> List[Tuple[Any, Optional[Dict[str, Any]]]]:
        completed = []
        while True:
            try:
                completed.append(self._results.get_nowait())
            except queue.Empty:
                break
        return completed

    def inflight_count(self) -> int:
        with self._lock:
            return self._inflight

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False)
