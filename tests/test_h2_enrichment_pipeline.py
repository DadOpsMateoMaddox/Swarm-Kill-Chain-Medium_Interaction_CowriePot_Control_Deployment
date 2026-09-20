"""H2 webhook/enrichment behavioral validation -- the acceptance-criteria
matrix, run through the REAL production code path (SessionClusterManager ->
ThreatIntelBroker -> ThreatIntelWorker -> build_session_summary_payload ->
discord-monitor's queue/drain), not just at the individual-module level
test_threat_intel.py and test_threat_intel_worker.py already cover.

Every provider network call is mocked at the `lookup_ip` boundary (same
convention as test_threat_intel.py) -- no test here ever contacts a real
provider, and TEST-NET (RFC 5737) addresses are NOT used as the "known
public IP" fixture, because observables.parse_public_ip correctly rejects
them (they are classified private/reserved by Python's ipaddress module);
8.8.8.8 is used instead, matching test_threat_intel.py's own convention.
Discord delivery is likewise always a mocked "test webhook"
(urllib.request.urlopen), never a real endpoint.

Scope, mapped to the reviewed acceptance criteria:
  1. enrichment success                 -> EnrichmentSuccessTests
  2. no-data response                   -> NoDataResponseTests
  3. timeout                            -> TimeoutTests
  4. HTTP 429                           -> RateLimitedTests
  5. provider 5xx                       -> ServerErrorTests
  6. cache hit                          -> CacheHitTests
  7. cache expiry                       -> CacheExpiryTests
  8. duplicate event                    -> DuplicateEventTests
  9. malformed/partial Cowrie event     -> MalformedEventTests
  10. CRITICAL: enrichment failure never suppresses the base alert
                                         -> BaseAlertSurvivesEnrichmentFailureTests
  E2E (step 6): one realistic, entirely synthetic cowrie.session/login
  fixture, replayed through enrichment -> Discord payload builder -> a
  mocked test webhook, proving the transformation (raw event identity +
  enrichment fields both present in the delivered card), not merely 2xx
  delivery.                             -> EndToEndFixtureTest
"""

import hashlib
import json
import logging
import sys
import tempfile
import time
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "native"))

import importlib.util  # noqa: E402


def load_script(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "native" / filename)
    module = importlib.util.module_from_spec(spec)
    with mock.patch.object(sys, "argv", [filename, "--self-test"]):
        spec.loader.exec_module(module)
    return module


discord = load_script("patriotpot_discord_h2pipeline_test", "discord-monitor.py")

from threat_intel.broker import ThreatIntelBroker  # noqa: E402
from threat_intel.cache import EnrichmentCache  # noqa: E402
from threat_intel.worker import ThreatIntelWorker  # noqa: E402
from threat_intel.provider_result import (  # noqa: E402
    STATUS_ERROR,
    STATUS_NOT_FOUND,
    STATUS_OK,
    STATUS_RATE_LIMITED,
    STATUS_TIMEOUT,
)

QUIET_LOGGER = logging.getLogger("test-h2-enrichment-pipeline")
QUIET_LOGGER.addHandler(logging.NullHandler())
QUIET_LOGGER.propagate = False

KNOWN_PUBLIC_IP = "8.8.8.8"  # not TEST-NET -- see module docstring


# ---------------------------------------------------------------------------
# Shared fixture builders
# ---------------------------------------------------------------------------

def make_login_event(src_ip=KNOWN_PUBLIC_IP, session="65c682df317d", username="root", password="toor"):
    """Structurally realistic cowrie.login.success event: same field shape
    observed in the real October 16 corpus (evidence/AUTH-PARITY-GATE.md),
    entirely synthetic content -- no real attacker IP or credential from
    that corpus is reproduced here."""
    return {
        "eventid": "cowrie.login.success",
        "timestamp": "2026-10-16T03:14:07.000000Z",
        "session": session,
        "src_ip": src_ip,
        "username": username,
        "password": password,
    }


def make_session_connect_event(src_ip=KNOWN_PUBLIC_IP, session="65c682df317d"):
    return {
        "eventid": "cowrie.session.connect",
        "timestamp": "2026-10-16T03:14:05.000000Z",
        "session": session,
        "src_ip": src_ip,
    }


def broker_with_cache(tmp_dir, parameter_values=None, ttl_seconds=None, rate_governor_clock=None):
    registry = mock.Mock()
    parameter_values = parameter_values or {"greynoise": "k", "virustotal": "k", "shodan": "k"}
    registry.get.side_effect = lambda name: parameter_values.get(name)
    cache = EnrichmentCache(Path(tmp_dir) / "cache.json")
    broker = ThreatIntelBroker(
        registry, cache, QUIET_LOGGER, timeout_seconds=1.0,
        ttl_seconds=ttl_seconds, rate_governor_clock=rate_governor_clock,
    )
    return broker, cache


def ok_response(normalized, raw_body=b'{"ok":true}'):
    return mock.Mock(status=STATUS_OK, http_status=200, normalized=normalized, raw_body=raw_body, retry_after_seconds=None)


def not_found_response():
    return mock.Mock(status=STATUS_NOT_FOUND, http_status=404, normalized={}, raw_body=b"{}", retry_after_seconds=None)


def timeout_response():
    return mock.Mock(status=STATUS_TIMEOUT, http_status=None, normalized={}, raw_body=None, retry_after_seconds=None)


def rate_limited_response(retry_after=30.0):
    return mock.Mock(status=STATUS_RATE_LIMITED, http_status=429, normalized={}, raw_body=None, retry_after_seconds=retry_after)


def server_error_response():
    return mock.Mock(status=STATUS_ERROR, http_status=502, normalized={}, raw_body=b"", retry_after_seconds=None)


def build_summary_fields(payload):
    return {f["name"]: f["value"] for f in payload["embeds"][0]["fields"]}


# ---------------------------------------------------------------------------
# 1. Enrichment success
# ---------------------------------------------------------------------------

class EnrichmentSuccessTests(unittest.TestCase):
    def test_known_public_ip_populates_expected_fields_and_preserves_base_cowrie_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            broker, _cache = broker_with_cache(tmp)
            with mock.patch("threat_intel.broker.greynoise.lookup_ip") as gn, mock.patch(
                "threat_intel.broker.virustotal.lookup_ip"
            ) as vt, mock.patch("threat_intel.broker.shodan.lookup_ip") as sh:
                gn.return_value = ok_response({"classification": "malicious", "actor": "known-scanner", "tags": ["scanner"]})
                vt.return_value = ok_response({"last_analysis_stats": {"malicious": 5, "suspicious": 2}, "asn": 15169, "as_owner": "GOOGLE"})
                sh.return_value = ok_response({"org": "Google LLC", "ports": [22, 80], "products": ["OpenSSH"], "vulns": []})
                enrichment = broker.enrich_ip(KNOWN_PUBLIC_IP)

            cluster = discord.SessionCluster(key="session:s1", src_ip=KNOWN_PUBLIC_IP, session_id="65c682df317d", created_at=0.0)
            cluster.record_event(make_login_event(), now=1.0, max_commands=50)
            cluster.raw_event_count = 2
            payload = discord.build_session_summary_payload(cluster, enrichment)

            fields = build_summary_fields(payload)
            self.assertIn("Classification: malicious", fields["GreyNoise"])
            self.assertIn("Actor: known-scanner", fields["GreyNoise"])
            self.assertIn("Malicious: 5", fields["VirusTotal"])
            self.assertIn("Owner: GOOGLE", fields["VirusTotal"])
            self.assertIn("Org: Google LLC", fields["Shodan"])
            self.assertIn("OpenSSH", fields["Shodan"])

            # Base Cowrie identity fields must survive enrichment being
            # present, not be overwritten or displaced by it.
            description = payload["embeds"][0]["description"]
            self.assertIn(KNOWN_PUBLIC_IP, description)
            self.assertIn("65c682df317d", description)
            self.assertIn("Successful login", fields["Authentication"])
            self.assertIn("root", fields["Authentication"])


# ---------------------------------------------------------------------------
# 2. No-data response
# ---------------------------------------------------------------------------

class NoDataResponseTests(unittest.TestCase):
    def test_no_data_still_delivers_alert_with_not_found_status(self):
        """This codebase's status vocabulary calls the "no data for this
        observable" outcome STATUS_NOT_FOUND ("not_found"), not "no_data" --
        provider_result.py's own comment: "'ok' and 'not_found' are the only
        statuses carrying meaningful `normalized` data." This test proves
        the acceptance criterion's *behavior* (alert still delivered, status
        is the well-defined "no data for this observable" outcome) under
        that existing vocabulary rather than silently introducing a second,
        divergent status string."""
        with tempfile.TemporaryDirectory() as tmp:
            broker, _cache = broker_with_cache(tmp)
            with mock.patch("threat_intel.broker.greynoise.lookup_ip") as gn, mock.patch(
                "threat_intel.broker.virustotal.lookup_ip"
            ) as vt, mock.patch("threat_intel.broker.shodan.lookup_ip") as sh:
                gn.return_value = not_found_response()
                vt.return_value = not_found_response()
                sh.return_value = not_found_response()
                enrichment = broker.enrich_ip(KNOWN_PUBLIC_IP)

            for provider in ("greynoise", "virustotal", "shodan"):
                self.assertEqual(enrichment[provider]["status"], STATUS_NOT_FOUND)

            cluster = discord.SessionCluster(key="session:s1", src_ip=KNOWN_PUBLIC_IP, session_id="s1", created_at=0.0)
            cluster.raw_event_count = 1
            payload = discord.build_session_summary_payload(cluster, enrichment)
            fields = build_summary_fields(payload)
            self.assertEqual(fields["GreyNoise"], STATUS_NOT_FOUND)
            self.assertEqual(fields["VirusTotal"], STATUS_NOT_FOUND)
            self.assertEqual(fields["Shodan"], STATUS_NOT_FOUND)
            # The alert (summary embed) is still a fully formed, deliverable
            # payload -- absence of provider data never blocks delivery.
            self.assertIn("embeds", payload)
            self.assertTrue(payload["embeds"][0]["fields"])


# ---------------------------------------------------------------------------
# 3. Timeout
# ---------------------------------------------------------------------------

class TimeoutTests(unittest.TestCase):
    def test_timeout_still_delivers_alert_bounded_no_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            broker, _cache = broker_with_cache(tmp)
            with mock.patch("threat_intel.broker.greynoise.lookup_ip") as gn, mock.patch(
                "threat_intel.broker.virustotal.lookup_ip"
            ) as vt, mock.patch("threat_intel.broker.shodan.lookup_ip") as sh:
                gn.return_value = timeout_response()
                vt.return_value = ok_response({"last_analysis_stats": {"malicious": 0}, "asn": 1, "as_owner": "x"})
                sh.return_value = ok_response({"org": "x", "ports": [], "products": [], "vulns": []})
                try:
                    enrichment = broker.enrich_ip(KNOWN_PUBLIC_IP)
                except Exception as exc:  # noqa: BLE001
                    self.fail(f"broker.enrich_ip raised on provider timeout: {exc!r}")

            self.assertEqual(enrichment["greynoise"]["status"], STATUS_TIMEOUT)
            self.assertEqual(enrichment["virustotal"]["status"], STATUS_OK)  # one provider timing out never blocks the others

            cluster = discord.SessionCluster(key="session:s1", src_ip=KNOWN_PUBLIC_IP, session_id="s1", created_at=0.0)
            cluster.raw_event_count = 1
            payload = discord.build_session_summary_payload(cluster, enrichment)
            fields = build_summary_fields(payload)
            self.assertEqual(fields["GreyNoise"], STATUS_TIMEOUT)
            self.assertTrue(payload["embeds"])  # a valid, deliverable payload -- not None, not a partial structure

    def test_full_worker_pipeline_survives_a_hanging_provider(self):
        """Same failure, exercised through the real async ThreatIntelWorker
        used in production, not just a direct broker call."""
        with tempfile.TemporaryDirectory() as tmp:
            broker, _cache = broker_with_cache(tmp)
            with mock.patch("threat_intel.broker.greynoise.lookup_ip", return_value=timeout_response()), mock.patch(
                "threat_intel.broker.virustotal.lookup_ip", return_value=timeout_response()
            ), mock.patch("threat_intel.broker.shodan.lookup_ip", return_value=timeout_response()):
                worker = ThreatIntelWorker(broker, max_workers=2, max_inflight=8)
                state = discord.default_state()
                clusters = discord.SessionClusterManager(window_seconds=-1.0)
                with mock.patch.object(discord.time, "time", return_value=0.0):
                    clusters.observe(make_session_connect_event(), now=0.0)
                with mock.patch.object(discord, "save_state"), mock.patch.object(discord.time, "time", return_value=100.0):
                    discord.flush_expired_clusters(state, clusters, worker)
                    deadline = time.monotonic() + 3.0
                    while time.monotonic() < deadline and not state["pending_intel"]:
                        discord.flush_expired_clusters(state, discord.SessionClusterManager(), worker)
                        time.sleep(0.02)
                worker.shutdown()
        self.assertEqual(len(state["pending_intel"]), 1)


# ---------------------------------------------------------------------------
# 4. HTTP 429
# ---------------------------------------------------------------------------

class RateLimitedTests(unittest.TestCase):
    def test_bounded_retry_no_message_storm_base_alert_survives(self):
        """A burst of many distinct-IP clusters, all hitting a provider that
        immediately 429s. Bounded retry/backoff (ProviderRateGovernor,
        already unit-tested in test_threat_intel.py) must keep call counts
        bounded; this test's own job is the pipeline-level guarantee: every
        cluster's summary is still delivered exactly once (no storm of
        extra "rate limited" notifications, no dropped summaries)."""
        with tempfile.TemporaryDirectory() as tmp:
            fake_clock = {"t": 0.0}
            broker, _cache = broker_with_cache(tmp, rate_governor_clock=lambda: fake_clock["t"])
            with mock.patch("threat_intel.broker.greynoise.lookup_ip", return_value=rate_limited_response(30.0)) as gn, mock.patch(
                "threat_intel.broker.virustotal.lookup_ip", return_value=ok_response({})
            ), mock.patch("threat_intel.broker.shodan.lookup_ip", return_value=ok_response({})):
                results = []
                for i in range(25):
                    results.append(broker.enrich_ip(f"8.8.{i}.1"))
                    fake_clock["t"] += 0.01  # far less than the 30s cooldown

            # Governor-global cooldown: only the FIRST call actually reached
            # the network; every subsequent distinct IP was short-circuited
            # by the provider-global governor, not queued or retried.
            self.assertEqual(gn.call_count, 1)
            for envelope in results:
                self.assertIn(envelope["greynoise"]["status"], (STATUS_RATE_LIMITED,))

            # Pipeline guarantee: one summary per cluster, no storm, none
            # dropped, regardless of the 429.
            state = discord.default_state()
            for i, enrichment in enumerate(results):
                cluster = discord.SessionCluster(key=f"session:s{i}", src_ip=f"8.8.{i}.1", session_id=f"s{i}", created_at=0.0)
                cluster.raw_event_count = 1
                discord._enqueue_summary(state, cluster, enrichment, discord._flush_item_id(cluster))
            self.assertEqual(len(state["pending_intel"]), 25)


# ---------------------------------------------------------------------------
# 5. Provider 5xx
# ---------------------------------------------------------------------------

class ServerErrorTests(unittest.TestCase):
    def test_5xx_degrades_gracefully_base_alert_survives(self):
        with tempfile.TemporaryDirectory() as tmp:
            broker, _cache = broker_with_cache(tmp)
            with mock.patch("threat_intel.broker.greynoise.lookup_ip", return_value=server_error_response()), mock.patch(
                "threat_intel.broker.virustotal.lookup_ip", return_value=ok_response({"last_analysis_stats": {"malicious": 1}, "asn": 1, "as_owner": "x"})
            ), mock.patch("threat_intel.broker.shodan.lookup_ip", return_value=ok_response({"org": "x", "ports": [], "products": [], "vulns": []})):
                enrichment = broker.enrich_ip(KNOWN_PUBLIC_IP)

            self.assertEqual(enrichment["greynoise"]["status"], STATUS_ERROR)
            self.assertEqual(enrichment["virustotal"]["status"], STATUS_OK)

            cluster = discord.SessionCluster(key="session:s1", src_ip=KNOWN_PUBLIC_IP, session_id="s1", created_at=0.0)
            cluster.raw_event_count = 1
            payload = discord.build_session_summary_payload(cluster, enrichment)
            fields = build_summary_fields(payload)
            self.assertEqual(fields["GreyNoise"], STATUS_ERROR)
            self.assertIn("Malicious: 1", fields["VirusTotal"])  # unaffected provider still renders real data
            self.assertTrue(payload["embeds"])


# ---------------------------------------------------------------------------
# 6. Cache hit -- provider call counts captured explicitly
# ---------------------------------------------------------------------------

class CacheHitTests(unittest.TestCase):
    def test_cache_hit_makes_zero_additional_provider_requests(self):
        with tempfile.TemporaryDirectory() as tmp:
            broker, cache = broker_with_cache(tmp)
            with mock.patch("threat_intel.broker.greynoise.lookup_ip", return_value=ok_response({"classification": "benign"})) as gn, mock.patch(
                "threat_intel.broker.virustotal.lookup_ip", return_value=ok_response({})
            ) as vt, mock.patch("threat_intel.broker.shodan.lookup_ip", return_value=ok_response({})) as sh:
                first = broker.enrich_ip(KNOWN_PUBLIC_IP)
                self.assertEqual((gn.call_count, vt.call_count, sh.call_count), (1, 1, 1))
                second = broker.enrich_ip(KNOWN_PUBLIC_IP)
                third = broker.enrich_ip(KNOWN_PUBLIC_IP)

            # The precise assertion the acceptance criterion asks for: call
            # counts, not merely "the output looked the same".
            self.assertEqual(gn.call_count, 1, "cache hit must not re-invoke the provider")
            self.assertEqual(vt.call_count, 1)
            self.assertEqual(sh.call_count, 1)
            self.assertFalse(first["greynoise"]["cache_hit"])
            self.assertTrue(second["greynoise"]["cache_hit"])
            self.assertTrue(third["greynoise"]["cache_hit"])
            self.assertEqual(second["greynoise"]["normalized"], first["greynoise"]["normalized"])

    def test_cache_hit_still_produces_a_deliverable_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            broker, _cache = broker_with_cache(tmp)
            with mock.patch("threat_intel.broker.greynoise.lookup_ip", return_value=ok_response({"classification": "benign"})), mock.patch(
                "threat_intel.broker.virustotal.lookup_ip", return_value=ok_response({})
            ), mock.patch("threat_intel.broker.shodan.lookup_ip", return_value=ok_response({})):
                broker.enrich_ip(KNOWN_PUBLIC_IP)  # populate cache
                cached_enrichment = broker.enrich_ip(KNOWN_PUBLIC_IP)  # served from cache
            cluster = discord.SessionCluster(key="session:s1", src_ip=KNOWN_PUBLIC_IP, session_id="s1", created_at=0.0)
            cluster.raw_event_count = 1
            payload = discord.build_session_summary_payload(cluster, cached_enrichment)
            self.assertIn("benign", build_summary_fields(payload)["GreyNoise"])


# ---------------------------------------------------------------------------
# 7. Cache expiry -- lookup refreshes
# ---------------------------------------------------------------------------

class CacheExpiryTests(unittest.TestCase):
    def test_expired_entry_triggers_a_fresh_provider_call(self):
        # Both the cache's TTL clock AND the rate governor's own
        # (independent, real-monotonic-by-default) clock must be driven
        # together here: the governor's 0.2s min-interval was silently
        # eating the third call in an earlier version of this test (it read
        # real wall-clock time, which had not advanced 0.2s between two
        # in-process calls), making `gn2` never get invoked at all --
        # nothing to do with cache expiry, purely a same-instant-calls
        # artifact of the governor's default clock choice.
        fake_time = {"t": 1_000_000.0}
        with tempfile.TemporaryDirectory() as tmp:
            broker, _cache = broker_with_cache(
                tmp,
                ttl_seconds={"greynoise": 60.0, "virustotal": 60.0, "shodan": 60.0},
                rate_governor_clock=lambda: fake_time["t"],
            )
            with mock.patch("threat_intel.cache.time.time", side_effect=lambda: fake_time["t"]):
                with mock.patch("threat_intel.broker.greynoise.lookup_ip", return_value=ok_response({"classification": "first"})) as gn, mock.patch(
                    "threat_intel.broker.virustotal.lookup_ip", return_value=ok_response({})
                ), mock.patch("threat_intel.broker.shodan.lookup_ip", return_value=ok_response({})):
                    first = broker.enrich_ip(KNOWN_PUBLIC_IP)
                    self.assertEqual(gn.call_count, 1)

                    fake_time["t"] += 30.0  # still within the 60s TTL
                    still_cached = broker.enrich_ip(KNOWN_PUBLIC_IP)
                    self.assertEqual(gn.call_count, 1, "within TTL: no refresh expected")
                    self.assertTrue(still_cached["greynoise"]["cache_hit"])

                with mock.patch(
                    "threat_intel.broker.greynoise.lookup_ip", return_value=ok_response({"classification": "refreshed"})
                ) as gn2, mock.patch("threat_intel.broker.virustotal.lookup_ip", return_value=ok_response({})), mock.patch(
                    "threat_intel.broker.shodan.lookup_ip", return_value=ok_response({})
                ):
                    fake_time["t"] += 60.0  # now past the 60s TTL from the first write
                    refreshed = broker.enrich_ip(KNOWN_PUBLIC_IP)

            self.assertEqual(gn2.call_count, 1, "expired entry must trigger exactly one fresh provider call")
            self.assertFalse(refreshed["greynoise"]["cache_hit"])
            self.assertEqual(refreshed["greynoise"]["normalized"]["classification"], "refreshed")
            self.assertNotEqual(first["greynoise"]["normalized"], refreshed["greynoise"]["normalized"])


# ---------------------------------------------------------------------------
# 8. Duplicate event
# ---------------------------------------------------------------------------

class DuplicateEventTests(unittest.TestCase):
    def test_identical_raw_line_replayed_twice_is_absorbed_once(self):
        """Complements test_sidecars.py's
        test_duplicate_line_absorbed_once_into_cluster: this asserts the
        same invariant with the H2 pipeline's own fixture shape and also
        checks that a duplicate never causes a second immediate alert."""
        state = discord.default_state()
        clusters = discord.SessionClusterManager(window_seconds=45.0)
        line = json.dumps(make_login_event()).encode("utf-8") + b"\n"
        with mock.patch.object(discord, "IMMEDIATE_ALERTS_ENABLED", True):
            discord.queue_line(state, line, clusters)
            discord.queue_line(state, line, clusters)  # exact duplicate bytes
            discord.queue_line(state, line, clusters)

        cluster = clusters._clusters["session:65c682df317d"]
        self.assertEqual(cluster.raw_event_count, 1, "duplicate raw lines must not be absorbed more than once")
        self.assertEqual(len(state["pending_legacy"]), 1, "duplicate must not produce a second immediate alert")
        self.assertEqual(len(state["seen"]), 1)

    def test_same_ip_enriched_twice_within_ttl_is_a_cache_hit_not_a_duplicate_provider_call(self):
        """The "duplicate" acceptance criterion at the enrichment layer:
        two distinct clusters (or a re-flush) for the same IP within TTL
        must not double up on provider calls -- this is CacheHitTests'
        concern restated in dedup terms, made explicit here per the
        acceptance criteria list."""
        with tempfile.TemporaryDirectory() as tmp:
            broker, _cache = broker_with_cache(tmp)
            with mock.patch("threat_intel.broker.greynoise.lookup_ip", return_value=ok_response({})) as gn, mock.patch(
                "threat_intel.broker.virustotal.lookup_ip", return_value=ok_response({})
            ), mock.patch("threat_intel.broker.shodan.lookup_ip", return_value=ok_response({})):
                broker.enrich_ip(KNOWN_PUBLIC_IP)
                broker.enrich_ip(KNOWN_PUBLIC_IP)
            self.assertEqual(gn.call_count, 1)


# ---------------------------------------------------------------------------
# 9. Malformed / partial Cowrie event
# ---------------------------------------------------------------------------

class MalformedEventTests(unittest.TestCase):
    def test_truncated_json_line_does_not_raise_and_is_dropped(self):
        state = discord.default_state()
        clusters = discord.SessionClusterManager()
        try:
            discord.queue_line(state, b'{"eventid":"cowrie.login.success", "sr', clusters)
        except Exception as exc:  # noqa: BLE001
            self.fail(f"queue_line raised on truncated JSON: {exc!r}")
        self.assertEqual(clusters.active_count(), 0)
        self.assertEqual(len(state["seen"]), 1)  # marked seen so it is never retried as new
        self.assertEqual(state["pending_legacy"], [])
        self.assertEqual(state["pending_intel"], [])

    def test_valid_json_non_object_does_not_raise(self):
        state = discord.default_state()
        clusters = discord.SessionClusterManager()
        for line in (b"42\n", b'"just a string"\n', b"[1,2,3]\n", b"null\n"):
            try:
                discord.queue_line(state, line, clusters)
            except Exception as exc:  # noqa: BLE001
                self.fail(f"queue_line raised on non-object JSON {line!r}: {exc!r}")
        self.assertEqual(clusters.active_count(), 0)

    def test_event_missing_eventid_and_src_ip_does_not_raise_and_clusters_as_unknown(self):
        state = discord.default_state()
        clusters = discord.SessionClusterManager()
        line = json.dumps({"session": "s1"}).encode("utf-8") + b"\n"
        try:
            discord.queue_line(state, line, clusters)
        except Exception as exc:  # noqa: BLE001
            self.fail(f"queue_line raised on a partial event: {exc!r}")
        cluster = clusters._clusters["session:s1"]
        self.assertEqual(cluster.src_ip, "unknown")
        self.assertFalse(cluster.authenticated)

    def test_unknown_src_ip_enrichment_is_invalid_observable_not_a_crash_or_network_call(self):
        """Behavior explicitly defined for this case: a cluster with no
        usable src_ip must short-circuit to invalid_observable for every
        provider, with zero network calls -- never raise, never silently
        query "unknown" as if it were a real IP."""
        with tempfile.TemporaryDirectory() as tmp:
            broker, _cache = broker_with_cache(tmp)
            with mock.patch("urllib.request.urlopen") as urlopen:
                enrichment = broker.enrich_ip("unknown")
            urlopen.assert_not_called()
        for provider in ("greynoise", "virustotal", "shodan"):
            self.assertEqual(enrichment[provider]["status"], "invalid_observable")

        cluster = discord.SessionCluster(key="ip:unknown", src_ip="unknown", session_id=None, created_at=0.0)
        cluster.raw_event_count = 1
        payload = discord.build_session_summary_payload(cluster, enrichment)
        self.assertTrue(payload["embeds"])  # still a valid, deliverable payload

    def test_priority_event_with_missing_fields_does_not_raise_format_alert(self):
        """format_alert deliberately raises ValueError for an unsupported
        eventid (caught by queue_line); confirm the SUPPORTED-but-partial
        case (missing username/password on a login-success event) is
        handled by safe_value's "N/A" default rather than a KeyError."""
        state = discord.default_state()
        clusters = discord.SessionClusterManager()
        line = json.dumps({"eventid": "cowrie.login.success", "src_ip": "198.51.100.9"}).encode("utf-8") + b"\n"
        with mock.patch.object(discord, "IMMEDIATE_ALERTS_ENABLED", True):
            try:
                discord.queue_line(state, line, clusters)
            except Exception as exc:  # noqa: BLE001
                self.fail(f"queue_line raised on a login-success event missing username/password: {exc!r}")
        self.assertEqual(len(state["pending_legacy"]), 1)
        self.assertIn("unknown", state["pending_legacy"][0]["payload"]["embeds"][0]["description"])


# ---------------------------------------------------------------------------
# 10. CRITICAL INVARIANT: enrichment failure must never suppress the base alert
# ---------------------------------------------------------------------------

class BaseAlertSurvivesEnrichmentFailureTests(unittest.TestCase):
    def test_immediate_legacy_alert_never_calls_the_broker_at_all(self):
        """Structural proof, not merely behavioral: the immediate/legacy
        alert path is built and enqueued with ZERO threat-intel machinery
        even instantiated -- it is architecturally impossible for
        enrichment to suppress it, because nothing on this path ever
        touches the broker."""
        state = discord.default_state()
        clusters = discord.SessionClusterManager()
        line = json.dumps(make_login_event()).encode("utf-8") + b"\n"
        with mock.patch.object(discord, "IMMEDIATE_ALERTS_ENABLED", True):
            discord.queue_line(state, line, clusters)  # no broker/worker passed in at all
        self.assertEqual(len(state["pending_legacy"]), 1)

    def test_broker_exception_during_flush_does_not_suppress_the_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            broker, _cache = broker_with_cache(tmp)
            with mock.patch("threat_intel.broker.greynoise.lookup_ip", side_effect=RuntimeError("provider outage")), mock.patch(
                "threat_intel.broker.virustotal.lookup_ip", side_effect=RuntimeError("provider outage")
            ), mock.patch("threat_intel.broker.shodan.lookup_ip", side_effect=RuntimeError("provider outage")):
                worker = ThreatIntelWorker(broker, max_workers=2, max_inflight=8)
                state = discord.default_state()
                clusters = discord.SessionClusterManager(window_seconds=-1.0)
                with mock.patch.object(discord.time, "time", return_value=0.0):
                    clusters.observe(make_session_connect_event(), now=0.0)
                with mock.patch.object(discord, "save_state"), mock.patch.object(discord.time, "time", return_value=100.0):
                    discord.flush_expired_clusters(state, clusters, worker)
                    deadline = time.monotonic() + 3.0
                    while time.monotonic() < deadline and not state["pending_intel"]:
                        discord.flush_expired_clusters(state, discord.SessionClusterManager(), worker)
                        time.sleep(0.02)
                worker.shutdown()
        self.assertEqual(len(state["pending_intel"]), 1, "an all-providers-broken enrichment must still deliver the base summary")
        fields = build_summary_fields(state["pending_intel"][0]["payload"])
        self.assertEqual(fields["GreyNoise"], "unavailable")

    def test_no_worker_configured_delivers_summary_immediately_without_enrichment(self):
        state = discord.default_state()
        clusters = discord.SessionClusterManager(window_seconds=-1.0)
        with mock.patch.object(discord.time, "time", return_value=0.0):
            clusters.observe(make_session_connect_event(), now=0.0)
        with mock.patch.object(discord, "save_state"), mock.patch.object(discord.time, "time", return_value=100.0):
            discord.flush_expired_clusters(state, clusters, worker=None)
        self.assertEqual(len(state["pending_intel"]), 1)

    def test_worker_backlog_exhausted_delivers_summary_immediately(self):
        state = discord.default_state()
        clusters = discord.SessionClusterManager(window_seconds=-1.0)
        saturated_worker = mock.Mock()
        saturated_worker.try_submit.return_value = False  # backpressure: no capacity
        saturated_worker.drain_completed.return_value = []
        with mock.patch.object(discord.time, "time", return_value=0.0):
            clusters.observe(make_session_connect_event(), now=0.0)
        with mock.patch.object(discord, "save_state"), mock.patch.object(discord.time, "time", return_value=100.0):
            discord.flush_expired_clusters(state, clusters, saturated_worker)
        self.assertEqual(len(state["pending_intel"]), 1)


# ---------------------------------------------------------------------------
# E2E (step 6): one realistic, entirely synthetic fixture through the full
# chain, including a mocked "test webhook" -- proves transformation, not
# merely delivery.
# ---------------------------------------------------------------------------

class EndToEndFixtureTest(unittest.TestCase):
    def test_cowrie_login_fixture_through_enrichment_to_delivered_card(self):
        event = make_login_event(src_ip=KNOWN_PUBLIC_IP, session="65c682df317d", username="root", password="toor")
        connect_event = make_session_connect_event(src_ip=KNOWN_PUBLIC_IP, session="65c682df317d")

        state = discord.default_state()
        clusters = discord.SessionClusterManager(window_seconds=-1.0)

        with tempfile.TemporaryDirectory() as tmp:
            broker, _cache = broker_with_cache(tmp)
            with mock.patch("threat_intel.broker.greynoise.lookup_ip") as gn, mock.patch(
                "threat_intel.broker.virustotal.lookup_ip"
            ) as vt, mock.patch("threat_intel.broker.shodan.lookup_ip") as sh:
                gn.return_value = ok_response({"classification": "malicious", "actor": "known-scanner", "tags": ["scanner", "tor"]})
                vt.return_value = ok_response({"last_analysis_stats": {"malicious": 7, "suspicious": 1}, "asn": 15169, "as_owner": "GOOGLE"})
                sh.return_value = ok_response({"org": "Google LLC", "ports": [22], "products": ["OpenSSH 8.9"], "vulns": []})

                worker = ThreatIntelWorker(broker, max_workers=2, max_inflight=8)
                # cowrie.session/login fixture -> cluster
                with mock.patch.object(discord.time, "time", return_value=0.0):
                    discord.queue_line(state, json.dumps(connect_event).encode() + b"\n", clusters)
                    discord.queue_line(state, json.dumps(event).encode() + b"\n", clusters)

                # -> enrichment (real broker + real async worker) -> Discord payload builder
                with mock.patch.object(discord, "save_state"), mock.patch.object(discord.time, "time", return_value=100.0):
                    discord.flush_expired_clusters(state, clusters, worker)
                    deadline = time.monotonic() + 3.0
                    while time.monotonic() < deadline and not state["pending_intel"]:
                        discord.flush_expired_clusters(state, discord.SessionClusterManager(), worker)
                        time.sleep(0.02)
                worker.shutdown()

        self.assertEqual(len(state["pending_intel"]), 1, "the fixture must produce exactly one flushed summary")

        # -> test webhook: a mocked HTTP endpoint captures exactly what
        # would have been POSTed to Discord, and we assert on ITS received
        # content -- not merely that delivery returned 2xx.
        received = {}

        def fake_urlopen(request, timeout=15):
            received["body"] = json.loads(request.data.decode("utf-8"))
            received["url"] = request.full_url
            return mock.MagicMock(
                __enter__=mock.Mock(return_value=mock.Mock(status=204)),
                __exit__=mock.Mock(return_value=False),
            )

        credentials = mock.Mock()
        credentials.get.return_value = "https://discord.com/api/webhooks/TEST/test-webhook-token"
        governor = discord.DiscordRateGovernor(clock=lambda: 0.0)
        with mock.patch.object(discord.urllib.request, "urlopen", side_effect=fake_urlopen), mock.patch.object(discord, "save_state"):
            discord.drain_pending(state, credentials, governor, "intel")

        self.assertIn("body", received, "the test webhook must have received exactly one POST")
        self.assertEqual(received["url"], "https://discord.com/api/webhooks/TEST/test-webhook-token")
        card_text = json.dumps(received["body"])

        # Raw event identity survives the transformation:
        self.assertIn("65c682df317d", card_text)   # session
        self.assertIn(KNOWN_PUBLIC_IP, card_text)   # src_ip
        self.assertIn("root", card_text)            # username

        # Enrichment fields survive the transformation:
        self.assertIn("malicious", card_text)
        self.assertIn("known-scanner", card_text)
        self.assertIn("GOOGLE", card_text)
        self.assertIn("Google LLC", card_text)
        self.assertIn("OpenSSH 8.9", card_text)

        # And the delivery itself must have been treated as successful --
        # item removed from pending, not dead-lettered.
        self.assertEqual(state["pending_intel"], [])
        self.assertEqual(state["dead_letters"], [])

        # No real network path was ever exercised: allowed_mentions must
        # still be locked down even for enrichment-derived text (a
        # provider's `actor`/`tags` fields are untrusted input exactly like
        # attacker-controlled Cowrie fields -- session_cluster.py's own
        # stated invariant).
        self.assertEqual(received["body"]["allowed_mentions"], {"parse": []})


if __name__ == "__main__":
    unittest.main()
