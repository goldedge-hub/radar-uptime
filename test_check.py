#!/usr/bin/env python3
"""Testy automatu stanów monitora (bez sieci, bez gita, bez maili).

Uruchomienie::

    python3 -m unittest
    python3 test_check.py
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

import check


UTC = timezone.utc
NOW = datetime(2026, 1, 10, 12, 0, 0, tzinfo=UTC)


def result(name: str, ok: bool, **kwargs) -> check.CheckResult:
    return check.CheckResult(name=name, ok=ok, **kwargs)


def failing_site() -> list[check.CheckResult]:
    return [result("site_home", False, latency_ms=10, error="TestError: nie ma takiego hosta")]


def healthy_site() -> list[check.CheckResult]:
    return [result("site_home", True, status=200, latency_ms=12)]


def ssl(*, ok: bool, days: int) -> check.CheckResult:
    error = "" if ok else f"certyfikat SSL wygasa za {days}.0 dni (próg 14 dni)"
    return result(check.SSL_CHECK_NAME, ok, latency_ms=5, error=error, ssl_days=days)


class DecideTests(unittest.TestCase):
    def test_first_failure_no_alert(self):
        new_state, action = check.decide({}, failing_site(), NOW)
        self.assertEqual(action["kind"], "none")
        self.assertFalse(action["notify"])
        self.assertEqual(new_state["consecutive_failures"], 1)
        self.assertEqual(new_state["status"], "up")
        self.assertIsNone(new_state["down_since"])

    def test_second_consecutive_failure_alerts(self):
        state = {"status": "up", "consecutive_failures": 1}
        new_state, action = check.decide(state, failing_site(), NOW)
        self.assertEqual(action["kind"], "down")
        self.assertTrue(action["notify"])
        self.assertEqual(new_state["status"], "down")
        self.assertEqual(new_state["consecutive_failures"], 2)
        self.assertEqual(new_state["down_since"], check._iso(NOW))

    def test_reminder_suppressed_until_3h(self):
        state = {
            "status": "down",
            "consecutive_failures": 2,
            "down_since": check._iso(NOW),
            "last_down_notified_at": check._iso(NOW),
        }
        _, early = check.decide(state, failing_site(), NOW + timedelta(hours=1))
        self.assertEqual(early["kind"], "none")
        self.assertFalse(early["notify"])
        # Bez wysyłki stan się nie zmienia, więc nie ma commita na gałęzi `state`.
        self.assertFalse(early["state_changed"])

        _, on_time = check.decide(state, failing_site(), NOW + timedelta(hours=3, seconds=1))
        self.assertEqual(on_time["kind"], "reminder")
        self.assertTrue(on_time["notify"])
        self.assertTrue(on_time["state_changed"])

    def test_recovery_emits_ok_once(self):
        state = {
            "status": "down",
            "consecutive_failures": 2,
            "down_since": check._iso(NOW),
            "last_down_notified_at": check._iso(NOW),
        }
        later = NOW + timedelta(hours=2)
        new_state, action = check.decide(state, healthy_site(), later)
        self.assertEqual(action["kind"], "recovery")
        self.assertTrue(action["notify"])
        self.assertEqual(action["downtime_seconds"], 7200)
        self.assertEqual(new_state["status"], "up")
        self.assertIsNone(new_state["down_since"])

        _, again = check.decide(new_state, healthy_site(), later + timedelta(minutes=10))
        self.assertEqual(again["kind"], "none")
        self.assertFalse(again["notify"])

    def test_ssl_warning_once_per_24h(self):
        results = healthy_site() + [ssl(ok=False, days=5)]
        state1, action1 = check.decide({}, results, NOW)
        self.assertTrue(action1["ssl_warning"])

        state2, action2 = check.decide(state1, results, NOW + timedelta(hours=1))
        self.assertFalse(action2["ssl_warning"])

        _, action3 = check.decide(state2, results, NOW + timedelta(hours=25))
        self.assertTrue(action3["ssl_warning"])

    def test_force_fail_alerts_immediately(self):
        new_state, action = check.decide({}, failing_site(), NOW, force_fail=True)
        self.assertEqual(action["kind"], "down")
        self.assertTrue(action["notify"])
        self.assertEqual(new_state["consecutive_failures"], 1)
        self.assertEqual(new_state["status"], "down")

    def test_ssl_failure_alone_does_not_alert_as_site_down(self):
        results = healthy_site() + [ssl(ok=False, days=3)]
        _, action = check.decide({}, results, NOW)
        self.assertEqual(action["kind"], "none")
        self.assertFalse(action["notify"])
        self.assertTrue(action["ssl_warning"])

    def test_healthy_run_does_not_change_state(self):
        state = check._normalize({})
        new_state, action = check.decide(state, healthy_site(), NOW)
        self.assertFalse(action["state_changed"])
        self.assertEqual(new_state, state)

    def test_failure_run_changes_state(self):
        _, action = check.decide({}, failing_site(), NOW)
        self.assertTrue(action["state_changed"])


class MailTests(unittest.TestCase):
    def test_subject_down_lists_failed_checks(self):
        _, action = check.decide({}, failing_site(), NOW, force_fail=True)
        subject, text, html_body = check.build_mail(action, action["checks"], NOW)
        self.assertIn("[Radar] AWARIA strony:", subject)
        self.assertIn("strona główna", subject)
        self.assertIn("HTTP", text)
        self.assertIn("<html>", html_body)

    def test_subject_recovery(self):
        state = {
            "status": "down",
            "consecutive_failures": 2,
            "down_since": check._iso(NOW),
            "last_down_notified_at": check._iso(NOW),
        }
        _, action = check.decide(state, healthy_site(), NOW + timedelta(minutes=30))
        subject, text, _ = check.build_mail(action, action["checks"], NOW)
        self.assertEqual(subject, "[Radar] OK — strona działa")
        self.assertIn("Czas niedostępności", text)

    def test_missing_env_does_not_crash(self):
        _, action = check.decide({}, failing_site(), NOW, force_fail=True)
        # Pusta konfiguracja -> brak wysyłki, brak wyjątku.
        check.deliver_mails(action, action["checks"], NOW, env={})


if __name__ == "__main__":
    unittest.main(verbosity=2)
