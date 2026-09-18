"""Deterministic tests for the outbound Discord rate governor."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "native"))

from discord_rate_governor import DiscordRateGovernor  # noqa: E402


class FakeClock:
    def __init__(self, start=0.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class DiscordRateGovernorTests(unittest.TestCase):
    def test_first_send_is_allowed(self):
        governor = DiscordRateGovernor(clock=FakeClock())
        self.assertTrue(governor.can_send())

    def test_min_interval_blocks_immediate_second_send(self):
        clock = FakeClock()
        governor = DiscordRateGovernor(min_interval_seconds=1.0, clock=clock)
        governor.note_send_attempt()
        self.assertFalse(governor.can_send())
        clock.advance(1.0)
        self.assertTrue(governor.can_send())

    def test_429_enters_degraded_mode_and_blocks_sends(self):
        clock = FakeClock()
        governor = DiscordRateGovernor(default_cooldown_seconds=30.0, clock=clock)
        newly_degraded = governor.note_rate_limited()
        self.assertTrue(newly_degraded)
        self.assertTrue(governor.degraded)
        self.assertFalse(governor.can_send())

    def test_429_respects_retry_after(self):
        clock = FakeClock()
        governor = DiscordRateGovernor(clock=clock)
        governor.note_rate_limited(retry_after_seconds=10.0)
        clock.advance(9.0)
        self.assertFalse(governor.can_send())
        clock.advance(2.0)
        self.assertTrue(governor.can_send())

    def test_retry_after_is_bounded_to_max_cooldown(self):
        clock = FakeClock()
        governor = DiscordRateGovernor(max_cooldown_seconds=60.0, clock=clock)
        governor.note_rate_limited(retry_after_seconds=99999.0)
        clock.advance(61.0)
        self.assertTrue(governor.can_send())

    def test_second_429_does_not_report_newly_degraded_again(self):
        clock = FakeClock()
        governor = DiscordRateGovernor(clock=clock)
        first = governor.note_rate_limited()
        second = governor.note_rate_limited()
        self.assertTrue(first)
        self.assertFalse(second)

    def test_recovery_reports_suppressed_count_and_resets(self):
        clock = FakeClock()
        governor = DiscordRateGovernor(default_cooldown_seconds=5.0, clock=clock)
        governor.note_rate_limited()
        governor.note_blocked(queue_depth=7)
        governor.note_blocked(queue_depth=12)
        clock.advance(6.0)
        recovered, suppressed = governor.note_success()
        self.assertTrue(recovered)
        self.assertEqual(suppressed, 12)
        self.assertFalse(governor.degraded)

    def test_success_when_not_degraded_reports_no_recovery(self):
        governor = DiscordRateGovernor(clock=FakeClock())
        recovered, suppressed = governor.note_success()
        self.assertFalse(recovered)
        self.assertEqual(suppressed, 0)

    def test_note_blocked_is_noop_when_not_degraded(self):
        governor = DiscordRateGovernor(clock=FakeClock())
        governor.note_blocked(queue_depth=100)
        recovered, suppressed = governor.note_success()
        self.assertFalse(recovered)
        self.assertEqual(suppressed, 0)

    def test_repeated_429_extends_cooldown_from_latest_call(self):
        clock = FakeClock()
        governor = DiscordRateGovernor(default_cooldown_seconds=10.0, clock=clock)
        governor.note_rate_limited()
        clock.advance(8.0)
        governor.note_rate_limited()
        clock.advance(8.0)
        self.assertFalse(governor.can_send())


if __name__ == "__main__":
    unittest.main()
