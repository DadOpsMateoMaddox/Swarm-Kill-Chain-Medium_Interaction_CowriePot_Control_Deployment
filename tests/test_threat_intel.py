"""Deterministic, offline tests for the H2 threat-intelligence package.

Every HTTP call is mocked. No test in this file ever contacts a real
provider or a real IP address; TEST-NET (RFC 5737) addresses stand in for
"a public IP" and are rejected by observables.parse_public_ip exactly like
any other private/reserved address, which is itself one of the behaviors
under test.
"""

import json
import logging
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "native"))

from threat_intel import greynoise, observables, shodan, virustotal  # noqa: E402
from threat_intel.broker import ThreatIntelBroker  # noqa: E402
from threat_intel.cache import EnrichmentCache, cache_key  # noqa: E402
from threat_intel.parameter_store import ParameterRegistry, SsmSecureStringCache  # noqa: E402
from threat_intel.rate_governor import ProviderRateGovernor  # noqa: E402
from threat_intel.provider_result import (  # noqa: E402
    ProviderResponse,
    STATUS_MALFORMED,
    STATUS_MISSING_CREDENTIAL,
    STATUS_NOT_FOUND,
    STATUS_OK,
    STATUS_RATE_LIMITED,
    STATUS_UNAUTHORIZED,
)

QUIET_LOGGER = logging.getLogger("test-threat-intel")
QUIET_LOGGER.addHandler(logging.NullHandler())
QUIET_LOGGER.propagate = False


def _http_error(code, body=b"{}"):
    return urllib.error.HTTPError(
        url="https://example.invalid",
        code=code,
        msg="error",
        hdrs={},
        fp=mock.Mock(read=mock.Mock(return_value=body)),
    )


class ObservablesTests(unittest.TestCase):
    def test_valid_public_ip_accepted(self):
        self.assertIsNotNone(observables.parse_public_ip("8.8.8.8"))

    def test_private_ip_rejected(self):
        self.assertIsNone(observables.parse_public_ip("10.1.2.3"))
        self.assertIsNone(observables.parse_public_ip("192.168.1.1"))

    def test_loopback_and_link_local_rejected(self):
        self.assertIsNone(observables.parse_public_ip("127.0.0.1"))
        self.assertIsNone(observables.parse_public_ip("169.254.1.1"))

    def test_documentation_testnet_rejected(self):
        for candidate in ("192.0.2.1", "198.51.100.1", "203.0.113.1"):
            self.assertIsNone(observables.parse_public_ip(candidate), candidate)

    def test_garbage_string_rejected(self):
        self.assertIsNone(observables.parse_public_ip("'; DROP TABLE"))
        self.assertIsNone(observables.parse_public_ip("http://evil.example/"))
        self.assertIsNone(observables.parse_public_ip(""))
        self.assertIsNone(observables.parse_public_ip(None))

    def test_ipv6_public_accepted_private_rejected(self):
        self.assertIsNotNone(observables.parse_public_ip("2001:4860:4860::8888"))
        self.assertIsNone(observables.parse_public_ip("fe80::1"))

    def test_sha256_validation(self):
        valid = "a" * 64
        self.assertEqual(observables.parse_sha256(valid), valid)
        self.assertIsNone(observables.parse_sha256("not-a-hash"))
        self.assertIsNone(observables.parse_sha256("a" * 63))


class ParameterStoreTests(unittest.TestCase):
    def _run(self, returncode, stdout):
        completed = subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout)
        with mock.patch("threat_intel.parameter_store.subprocess.run", return_value=completed) as run:
            cache = SsmSecureStringCache("/x/y", "patriotpot", "us-east-1", QUIET_LOGGER)
            value = cache.get(force=True)
        return value, run

    def test_successful_fetch(self):
        value, run = self._run(0, "super-secret-value\n")
        self.assertEqual(value, "super-secret-value")
        run.assert_called_once()

    def test_missing_parameter_returns_none(self):
        value, _ = self._run(255, "")
        self.assertIsNone(value)

    def test_none_literal_treated_as_missing(self):
        value, _ = self._run(0, "None")
        self.assertIsNone(value)

    def test_refresh_is_cached_between_calls(self):
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="value-1")
        with mock.patch("threat_intel.parameter_store.subprocess.run", return_value=completed) as run:
            cache = SsmSecureStringCache("/x/y", "patriotpot", "us-east-1", QUIET_LOGGER)
            first = cache.get()
            second = cache.get()
        self.assertEqual(first, "value-1")
        self.assertEqual(second, "value-1")
        run.assert_called_once()

    def test_subprocess_timeout_yields_none_without_raising(self):
        with mock.patch(
            "threat_intel.parameter_store.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="aws", timeout=20),
        ):
            cache = SsmSecureStringCache("/x/y", "patriotpot", "us-east-1", QUIET_LOGGER)
            self.assertIsNone(cache.get(force=True))

    def test_registry_dispatches_by_provider_name(self):
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="k1")
        with mock.patch("threat_intel.parameter_store.subprocess.run", return_value=completed):
            registry = ParameterRegistry(
                {"greynoise": "/gn", "virustotal": "/vt"},
                "patriotpot",
                "us-east-1",
                QUIET_LOGGER,
            )
            self.assertEqual(registry.get("greynoise"), "k1")
            self.assertIsNone(registry.get("shodan"))
        self.assertEqual(registry.configured_providers(), ["greynoise", "virustotal"])


class CacheTests(unittest.TestCase):
    def test_set_then_get_within_ttl(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = EnrichmentCache(Path(tmp) / "cache.json")
            key = cache_key("greynoise", "ip", "8.8.8.8")
            cache.set(key, {"status": "ok"}, ttl_seconds=60)
            self.assertEqual(cache.get(key)["status"], "ok")

    def test_expired_entry_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = EnrichmentCache(Path(tmp) / "cache.json")
            key = cache_key("greynoise", "ip", "8.8.8.8")
            cache.set(key, {"status": "ok"}, ttl_seconds=-1)
            self.assertIsNone(cache.get(key))

    def test_persists_across_instances(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cache.json"
            cache_key_value = cache_key("shodan", "ip", "8.8.8.8")
            EnrichmentCache(path).set(cache_key_value, {"status": "ok"}, ttl_seconds=60)
            reloaded = EnrichmentCache(path)
            self.assertEqual(reloaded.get(cache_key_value)["status"], "ok")

    def test_bounded_eviction(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = EnrichmentCache(Path(tmp) / "cache.json", max_entries=3)
            for i in range(5):
                cache.set(cache_key("gn", "ip", f"1.1.1.{i}"), {"status": "ok"}, ttl_seconds=60 + i)
            self.assertLessEqual(len(cache._entries), 3)

    def test_corrupt_cache_file_recovers_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cache.json"
            path.write_text("not json", encoding="utf-8")
            cache = EnrichmentCache(path)
            self.assertIsNone(cache.get("anything"))


class ProviderTests(unittest.TestCase):
    def test_greynoise_success(self):
        payload = {
            "classification": "malicious",
            "noise": True,
            "riot": False,
            "actor": "unknown",
            "tags": ["SSH Bruteforcer"],
            "name": "unknown",
            "last_seen": "2026-01-01",
            "link": "https://viz.greynoise.io/ip/8.8.8.8",
        }
        body = json.dumps(payload).encode()
        with mock.patch("urllib.request.urlopen") as urlopen:
            urlopen.return_value.__enter__.return_value = mock.Mock(status=200, read=mock.Mock(return_value=body))
            result = greynoise.lookup_ip("8.8.8.8", "key", timeout=5)
        self.assertEqual(result.status, STATUS_OK)
        self.assertEqual(result.normalized["classification"], "malicious")
        self.assertEqual(result.normalized["tags"], ["SSH Bruteforcer"])

    def test_virustotal_success(self):
        payload = {
            "data": {
                "attributes": {
                    "reputation": -10,
                    "country": "US",
                    "asn": 15169,
                    "as_owner": "GOOGLE",
                    "last_analysis_stats": {"malicious": 9, "suspicious": 2, "harmless": 60, "undetected": 5},
                }
            }
        }
        body = json.dumps(payload).encode()
        with mock.patch("urllib.request.urlopen") as urlopen:
            urlopen.return_value.__enter__.return_value = mock.Mock(status=200, read=mock.Mock(return_value=body))
            result = virustotal.lookup_ip("8.8.8.8", "key", timeout=5)
        self.assertEqual(result.status, STATUS_OK)
        self.assertEqual(result.normalized["last_analysis_stats"]["malicious"], 9)
        self.assertEqual(result.normalized["as_owner"], "GOOGLE")

    def test_virustotal_file_hash_lookup_is_read_only(self):
        self.assertFalse(hasattr(virustotal, "upload_file"))
        self.assertFalse(hasattr(virustotal, "submit_file"))
        payload = {"data": {"attributes": {"sha256": "a" * 64, "last_analysis_stats": {}}}}
        body = json.dumps(payload).encode()
        with mock.patch("urllib.request.urlopen") as urlopen:
            urlopen.return_value.__enter__.return_value = mock.Mock(status=200, read=mock.Mock(return_value=body))
            result = virustotal.lookup_file_hash("a" * 64, "key", timeout=5)
        self.assertEqual(result.status, STATUS_OK)

    def test_shodan_success(self):
        payload = {
            "org": "Example Org",
            "isp": "Example ISP",
            "asn": "AS12345",
            "country_name": "US",
            "hostnames": ["host.example.com"],
            "domains": ["example.com"],
            "ports": [22, 80, 2375],
            "data": [{"product": "OpenSSH", "transport": "tcp"}, {"product": "nginx", "transport": "tcp"}],
            "last_update": "2026-01-01",
            "vulns": ["CVE-2024-0001"],
            "tags": ["cloud"],
        }
        body = json.dumps(payload).encode()
        with mock.patch("urllib.request.urlopen") as urlopen:
            urlopen.return_value.__enter__.return_value = mock.Mock(status=200, read=mock.Mock(return_value=body))
            result = shodan.lookup_ip("8.8.8.8", "key", timeout=5)
        self.assertEqual(result.status, STATUS_OK)
        self.assertEqual(result.normalized["ports"], [22, 80, 2375])
        self.assertIn("OpenSSH", result.normalized["products"])

    def test_404_not_found(self):
        with mock.patch("urllib.request.urlopen", side_effect=_http_error(404)):
            result = greynoise.lookup_ip("8.8.8.8", "key", timeout=5)
        self.assertEqual(result.status, STATUS_NOT_FOUND)

    def test_401_unauthorized(self):
        with mock.patch("urllib.request.urlopen", side_effect=_http_error(401)):
            result = virustotal.lookup_ip("8.8.8.8", "key", timeout=5)
        self.assertEqual(result.status, STATUS_UNAUTHORIZED)

    def test_403_forbidden_treated_as_unauthorized(self):
        with mock.patch("urllib.request.urlopen", side_effect=_http_error(403)):
            result = shodan.lookup_ip("8.8.8.8", "key", timeout=5)
        self.assertEqual(result.status, STATUS_UNAUTHORIZED)

    def test_429_rate_limited(self):
        with mock.patch("urllib.request.urlopen", side_effect=_http_error(429)):
            result = greynoise.lookup_ip("8.8.8.8", "key", timeout=5)
        self.assertEqual(result.status, STATUS_RATE_LIMITED)

    def test_500_server_error(self):
        with mock.patch("urllib.request.urlopen", side_effect=_http_error(500)):
            result = virustotal.lookup_ip("8.8.8.8", "key", timeout=5)
        self.assertEqual(result.status, "error")

    def test_timeout(self):
        with mock.patch("urllib.request.urlopen", side_effect=TimeoutError()):
            result = shodan.lookup_ip("8.8.8.8", "key", timeout=5)
        self.assertEqual(result.status, "timeout")

    def test_malformed_json(self):
        with mock.patch("urllib.request.urlopen") as urlopen:
            urlopen.return_value.__enter__.return_value = mock.Mock(status=200, read=mock.Mock(return_value=b"{not json"))
            result = greynoise.lookup_ip("8.8.8.8", "key", timeout=5)
        self.assertEqual(result.status, STATUS_MALFORMED)

    def test_missing_credential_short_circuits_without_network(self):
        with mock.patch("urllib.request.urlopen") as urlopen:
            result = greynoise.lookup_ip("8.8.8.8", "", timeout=5)
            result_vt = virustotal.lookup_ip("8.8.8.8", None, timeout=5)
            result_sh = shodan.lookup_ip("8.8.8.8", "", timeout=5)
        urlopen.assert_not_called()
        self.assertEqual(result.status, STATUS_MISSING_CREDENTIAL)
        self.assertEqual(result_vt.status, STATUS_MISSING_CREDENTIAL)
        self.assertEqual(result_sh.status, STATUS_MISSING_CREDENTIAL)


class BrokerTests(unittest.TestCase):
    def _broker(self, tmp_dir, parameter_values=None):
        registry = mock.Mock()
        parameter_values = parameter_values or {"greynoise": "k", "virustotal": "k", "shodan": "k"}
        registry.get.side_effect = lambda name: parameter_values.get(name)
        cache = EnrichmentCache(Path(tmp_dir) / "cache.json")
        return ThreatIntelBroker(registry, cache, QUIET_LOGGER, timeout_seconds=1.0), cache

    def test_private_ip_short_circuits_all_providers(self):
        with tempfile.TemporaryDirectory() as tmp:
            broker, _cache = self._broker(tmp)
            with mock.patch("urllib.request.urlopen") as urlopen:
                results = broker.enrich_ip("10.0.0.5")
            urlopen.assert_not_called()
        for provider in ("greynoise", "virustotal", "shodan"):
            self.assertEqual(results[provider]["status"], "invalid_observable")

    def test_fail_open_on_provider_exception(self):
        with tempfile.TemporaryDirectory() as tmp:
            broker, _cache = self._broker(tmp)
            with mock.patch("threat_intel.broker.greynoise.lookup_ip", side_effect=RuntimeError("boom")):
                with mock.patch("threat_intel.broker.virustotal.lookup_ip") as vt, mock.patch(
                    "threat_intel.broker.shodan.lookup_ip"
                ) as sh:
                    vt.return_value = mock.Mock(status=STATUS_OK, http_status=200, normalized={}, raw_body=b"{}")
                    sh.return_value = mock.Mock(status=STATUS_OK, http_status=200, normalized={}, raw_body=b"{}")
                    results = broker.enrich_ip("8.8.8.8")
        self.assertEqual(results["greynoise"]["status"], "unavailable")
        self.assertEqual(results["virustotal"]["status"], STATUS_OK)
        self.assertEqual(results["shodan"]["status"], STATUS_OK)

    def test_cache_hit_avoids_second_network_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            broker, _cache = self._broker(tmp)
            with mock.patch("threat_intel.broker.greynoise.lookup_ip") as gn, mock.patch(
                "threat_intel.broker.virustotal.lookup_ip"
            ) as vt, mock.patch("threat_intel.broker.shodan.lookup_ip") as sh:
                for mocked in (gn, vt, sh):
                    mocked.return_value = mock.Mock(status=STATUS_OK, http_status=200, normalized={"x": 1}, raw_body=b"{}")
                broker.enrich_ip("8.8.8.8")
                broker.enrich_ip("8.8.8.8")
            gn.assert_called_once()
            vt.assert_called_once()
            sh.assert_called_once()

    def test_missing_credential_does_not_break_other_providers(self):
        with tempfile.TemporaryDirectory() as tmp:
            broker, _cache = self._broker(tmp, {"greynoise": None, "virustotal": "k", "shodan": "k"})
            with mock.patch("threat_intel.broker.virustotal.lookup_ip") as vt, mock.patch(
                "threat_intel.broker.shodan.lookup_ip"
            ) as sh:
                vt.return_value = mock.Mock(status=STATUS_OK, http_status=200, normalized={}, raw_body=b"{}")
                sh.return_value = mock.Mock(status=STATUS_OK, http_status=200, normalized={}, raw_body=b"{}")
                results = broker.enrich_ip("8.8.8.8")
        self.assertEqual(results["greynoise"]["status"], STATUS_MISSING_CREDENTIAL)
        self.assertEqual(results["virustotal"]["status"], STATUS_OK)

    def test_provenance_fields_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            broker, _cache = self._broker(tmp)
            with mock.patch("threat_intel.broker.greynoise.lookup_ip") as gn, mock.patch(
                "threat_intel.broker.virustotal.lookup_ip"
            ) as vt, mock.patch("threat_intel.broker.shodan.lookup_ip") as sh:
                for mocked in (gn, vt, sh):
                    mocked.return_value = mock.Mock(status=STATUS_OK, http_status=200, normalized={}, raw_body=b'{"a":1}')
                results = broker.enrich_ip("8.8.8.8")
            envelope = results["greynoise"]
            for field in ("provider", "api_version", "observable_type", "observable", "queried_at", "status", "cache_hit", "response_sha256", "normalized"):
                self.assertIn(field, envelope)
            self.assertEqual(envelope["cache_hit"], False)


class FakeGovernorClock:
    def __init__(self, start=0.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class ProviderRateGovernorTests(unittest.TestCase):
    def test_first_call_allowed(self):
        governor = ProviderRateGovernor(clock=FakeGovernorClock())
        self.assertTrue(governor.can_call())

    def test_rate_limited_blocks_until_retry_after(self):
        clock = FakeGovernorClock()
        governor = ProviderRateGovernor(clock=clock)
        governor.note_rate_limited(retry_after_seconds=15.0)
        self.assertFalse(governor.can_call())
        clock.advance(14.0)
        self.assertFalse(governor.can_call())
        clock.advance(2.0)
        self.assertTrue(governor.can_call())

    def test_repeated_rate_limit_without_retry_after_backs_off_exponentially(self):
        clock = FakeGovernorClock()
        governor = ProviderRateGovernor(default_cooldown_seconds=10.0, max_cooldown_seconds=1000.0, clock=clock)
        governor.note_rate_limited()
        clock.advance(10.01)
        self.assertTrue(governor.can_call())
        governor.note_rate_limited()  # second consecutive, still no retry_after
        clock.advance(10.01)
        self.assertFalse(governor.can_call())  # 20s cooldown now, not recovered yet
        clock.advance(10.0)
        self.assertTrue(governor.can_call())

    def test_success_resets_backoff_counter(self):
        clock = FakeGovernorClock()
        governor = ProviderRateGovernor(default_cooldown_seconds=10.0, clock=clock)
        governor.note_rate_limited()
        governor.note_success()
        governor.note_rate_limited()
        clock.advance(10.01)
        self.assertTrue(governor.can_call())  # back to first-tier cooldown, not doubled

    def test_backoff_bounded_by_max_cooldown(self):
        clock = FakeGovernorClock()
        governor = ProviderRateGovernor(default_cooldown_seconds=100.0, max_cooldown_seconds=150.0, clock=clock)
        for _ in range(5):
            governor.note_rate_limited()
        clock.advance(151.0)
        self.assertTrue(governor.can_call())


class ProviderGlobalGovernanceIntegrationTests(unittest.TestCase):
    """Blocker 1 proof: a burst of distinct IPs must not each independently
    hit a provider that has started returning 429."""

    def _broker(self, tmp_dir, clock=None):
        registry = mock.Mock()
        registry.get.side_effect = lambda name: "k"
        cache = EnrichmentCache(Path(tmp_dir) / "cache.json")
        return ThreatIntelBroker(registry, cache, QUIET_LOGGER, timeout_seconds=1.0, rate_governor_clock=clock)

    def test_many_distinct_ips_after_429_cause_bounded_requests(self):
        with tempfile.TemporaryDirectory() as tmp:
            broker = self._broker(tmp)
            call_count = {"n": 0}

            def fake_lookup(ip, api_key, timeout):
                call_count["n"] += 1
                return ProviderResponse(status=STATUS_RATE_LIMITED, http_status=429, retry_after_seconds=9999.0)

            with mock.patch("threat_intel.broker.greynoise.lookup_ip", side_effect=fake_lookup):
                with mock.patch("threat_intel.broker.virustotal.lookup_ip") as vt, mock.patch(
                    "threat_intel.broker.shodan.lookup_ip"
                ) as sh:
                    vt.return_value = ProviderResponse(status=STATUS_OK, http_status=200, normalized={}, raw_body=b"{}")
                    sh.return_value = ProviderResponse(status=STATUS_OK, http_status=200, normalized={}, raw_body=b"{}")
                    # 50 distinct, genuinely public IPs -- IP validation itself is
                    # covered elsewhere; this test targets the governor specifically.
                    distinct_ips = [f"8.8.{i}.1" for i in range(1, 51)]
                    for ip in distinct_ips:
                        broker.enrich_ip(ip)
            # Exactly one real GreyNoise HTTP call: the first cache-miss IP that
            # triggered the 429. Every subsequent distinct IP must be skipped by
            # the provider-global governor before any network call.
            self.assertEqual(call_count["n"], 1)

    def test_governor_recovers_after_cooldown_and_resumes_calls(self):
        clock = FakeGovernorClock()
        with tempfile.TemporaryDirectory() as tmp:
            broker = self._broker(tmp, clock=clock)
            call_count = {"n": 0}

            def fake_lookup(ip, api_key, timeout):
                call_count["n"] += 1
                if call_count["n"] == 1:
                    return ProviderResponse(status=STATUS_RATE_LIMITED, http_status=429, retry_after_seconds=5.0)
                return ProviderResponse(status=STATUS_OK, http_status=200, normalized={}, raw_body=b"{}")

            with mock.patch("threat_intel.broker.greynoise.lookup_ip", side_effect=fake_lookup):
                with mock.patch("threat_intel.broker.virustotal.lookup_ip") as vt, mock.patch(
                    "threat_intel.broker.shodan.lookup_ip"
                ) as sh:
                    vt.return_value = ProviderResponse(status=STATUS_OK, http_status=200, normalized={}, raw_body=b"{}")
                    sh.return_value = ProviderResponse(status=STATUS_OK, http_status=200, normalized={}, raw_body=b"{}")
                    broker.enrich_ip("8.8.8.1")
                    clock.advance(6.0)
                    result = broker.enrich_ip("8.8.8.2")
            self.assertEqual(result["greynoise"]["status"], STATUS_OK)
            self.assertEqual(call_count["n"], 2)

    def test_fail_open_returns_normalized_rate_limited_status_not_exception(self):
        with tempfile.TemporaryDirectory() as tmp:
            broker = self._broker(tmp)
            with mock.patch(
                "threat_intel.broker.greynoise.lookup_ip",
                return_value=ProviderResponse(status=STATUS_RATE_LIMITED, http_status=429, retry_after_seconds=9999.0),
            ):
                with mock.patch("threat_intel.broker.virustotal.lookup_ip") as vt, mock.patch(
                    "threat_intel.broker.shodan.lookup_ip"
                ) as sh:
                    vt.return_value = ProviderResponse(status=STATUS_OK, http_status=200, normalized={}, raw_body=b"{}")
                    sh.return_value = ProviderResponse(status=STATUS_OK, http_status=200, normalized={}, raw_body=b"{}")
                    first = broker.enrich_ip("8.8.9.1")
                    second = broker.enrich_ip("8.8.9.2")
        self.assertEqual(first["greynoise"]["status"], STATUS_RATE_LIMITED)
        self.assertEqual(second["greynoise"]["status"], STATUS_RATE_LIMITED)


if __name__ == "__main__":
    unittest.main()
