"""Tests for the bounded background enrichment worker (Blocker 3 proof).

Proves: Cowrie log ingestion (offset consumption) is never blocked by
provider latency, even under a burst of hundreds of clusters and
deliberately slow mocked providers, and the worker fails open (bounded
backlog, broker exceptions never propagate).
"""

import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "native"))

from threat_intel.worker import ThreatIntelWorker  # noqa: E402


class FakeCluster:
    def __init__(self, key, src_ip):
        self.key = key
        self.src_ip = src_ip


class ThreatIntelWorkerTests(unittest.TestCase):
    def test_try_submit_is_non_blocking(self):
        broker = mock.Mock()
        broker.enrich_ip.side_effect = lambda ip: (time.sleep(0.2) or {"greynoise": {"status": "ok"}})
        worker = ThreatIntelWorker(broker, max_workers=2, max_inflight=8)
        started = time.monotonic()
        accepted = worker.try_submit(FakeCluster("session:s1", "8.8.8.1"))
        elapsed = time.monotonic() - started
        self.assertTrue(accepted)
        self.assertLess(elapsed, 0.05)  # returned immediately, did not wait for the 0.2s "provider"
        worker.shutdown()

    def test_backlog_bound_rejects_once_full(self):
        broker = mock.Mock()
        release = threading.Event()
        broker.enrich_ip.side_effect = lambda ip: (release.wait(2.0), {})[1]
        worker = ThreatIntelWorker(broker, max_workers=2, max_inflight=2)
        try:
            self.assertTrue(worker.try_submit(FakeCluster("k1", "8.8.8.1")))
            self.assertTrue(worker.try_submit(FakeCluster("k2", "8.8.8.2")))
            self.assertFalse(worker.try_submit(FakeCluster("k3", "8.8.8.3")))  # backlog full, no blocking
        finally:
            release.set()
            worker.shutdown()

    def test_results_drain_after_completion(self):
        broker = mock.Mock()
        broker.enrich_ip.return_value = {"greynoise": {"status": "ok"}}
        worker = ThreatIntelWorker(broker, max_workers=1, max_inflight=4)
        cluster = FakeCluster("session:s1", "8.8.8.1")
        worker.try_submit(cluster)
        deadline = time.monotonic() + 2.0
        completed = []
        while time.monotonic() < deadline and not completed:
            completed = worker.drain_completed()
            if not completed:
                time.sleep(0.01)
        worker.shutdown()
        self.assertEqual(len(completed), 1)
        result_cluster, enrichment = completed[0]
        self.assertIs(result_cluster, cluster)
        self.assertEqual(enrichment, {"greynoise": {"status": "ok"}})

    def test_broker_exception_fails_open_not_raised(self):
        broker = mock.Mock()
        broker.enrich_ip.side_effect = RuntimeError("provider outage")
        worker = ThreatIntelWorker(broker, max_workers=1, max_inflight=4)
        worker.try_submit(FakeCluster("session:s1", "8.8.8.1"))
        deadline = time.monotonic() + 2.0
        completed = []
        while time.monotonic() < deadline and not completed:
            completed = worker.drain_completed()
            if not completed:
                time.sleep(0.01)
        worker.shutdown()
        self.assertEqual(len(completed), 1)
        _cluster, enrichment = completed[0]
        self.assertIsNone(enrichment)  # fail-open: no exception escaped the worker

    def test_inflight_count_decrements_after_completion(self):
        broker = mock.Mock()
        broker.enrich_ip.return_value = {}
        worker = ThreatIntelWorker(broker, max_workers=1, max_inflight=4)
        worker.try_submit(FakeCluster("session:s1", "8.8.8.1"))
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline and worker.inflight_count() != 0:
            time.sleep(0.01)
        worker.shutdown()
        self.assertEqual(worker.inflight_count(), 0)


class IngestionNonBlockingStressTest(unittest.TestCase):
    """Blocker 3's explicit proof requirement: hundreds of unique clusters,
    deliberately slow mocked providers, ingestion (offset consumption)
    proceeds independently of provider latency."""

    def test_hundreds_of_slow_clusters_do_not_block_submission(self):
        broker = mock.Mock()
        # Each "provider" call sleeps -- if flush_expired_clusters called
        # this synchronously per cluster, 300 clusters * 0.05s would take
        # 15+ seconds. The worker must return from try_submit immediately
        # regardless.
        broker.enrich_ip.side_effect = lambda ip: (time.sleep(0.05) or {})
        worker = ThreatIntelWorker(broker, max_workers=8, max_inflight=500)

        started = time.monotonic()
        submitted = 0
        for i in range(300):
            cluster = FakeCluster(f"session:s{i}", f"8.8.{i % 250}.1")
            if worker.try_submit(cluster):
                submitted += 1
        submission_elapsed = time.monotonic() - started

        # Submitting 300 jobs must be fast -- bounded by dispatch overhead,
        # not by 300 * 0.05s of simulated provider latency.
        self.assertLess(submission_elapsed, 1.0)
        self.assertEqual(submitted, 300)

        deadline = time.monotonic() + 10.0
        completed = []
        while time.monotonic() < deadline and len(completed) < 300:
            completed.extend(worker.drain_completed())
            if len(completed) < 300:
                time.sleep(0.02)
        worker.shutdown()
        self.assertEqual(len(completed), 300)


if __name__ == "__main__":
    unittest.main()
