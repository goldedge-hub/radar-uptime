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
    def test_default_threshold_alerts_on_first_confirmed_failure(self):
        # Failures are already confirmed for ~3 min inside the run
        # (run_checks_confirmed), so the first failed run alerts.
        _, action = check.decide({}, failing_site(), NOW)
        self.assertEqual(action["kind"], "down")
        self.assertTrue(action["notify"])

    def test_first_failure_no_alert(self):
        new_state, action = check.decide({}, failing_site(), NOW, fail_threshold=2)
        self.assertEqual(action["kind"], "none")
        self.assertFalse(action["notify"])
        self.assertEqual(new_state["consecutive_failures"], 1)
        self.assertEqual(new_state["status"], "up")
        self.assertIsNone(new_state["down_since"])

    def test_second_consecutive_failure_alerts(self):
        state = {"status": "up", "consecutive_failures": 1}
        new_state, action = check.decide(state, failing_site(), NOW, fail_threshold=2)
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

    def test_alert_bcc_copy(self):
        import json

        sent = []

        def poster(data, api_key):
            sent.append(json.loads(data))
            return 200

        _, action = check.decide({}, failing_site(), NOW, force_fail=True)
        env = {"RESEND_API_KEY": "k", "ALERT_TO": "owner@example.com", "ALERT_BCC": "copy@example.com"}
        check.deliver_mails(action, action["checks"], NOW, env=env, poster=poster)
        self.assertEqual(sent[0]["to"], ["owner@example.com"])
        self.assertEqual(sent[0]["bcc"], ["copy@example.com"])

        sent.clear()
        env["ALERT_TO_OVERRIDE"] = "test@example.com"
        check.deliver_mails(action, action["checks"], NOW, env=env, poster=poster)
        self.assertEqual(sent[0]["to"], ["test@example.com"])
        self.assertNotIn("bcc", sent[0])


class DnsRetryTests(unittest.TestCase):
    def test_dns_error_is_retried_with_fresh_resolution(self):
        calls = []
        answers = [
            (None, "", "URLError: <urlopen error [Errno -2] Name or service not known>"),
            (200, "Radar", ""),
        ]

        def once(url, timeout):
            calls.append(url)
            return answers.pop(0)

        slept = []
        status, body, error = check._get_resolving(
            "https://radarnieruchomosci.com/", 1.0, once=once, sleep=slept.append
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(calls), 2)
        self.assertEqual(slept, [check.DNS_RETRY_DELAYS[0]])

    def test_non_dns_error_is_not_retried_here(self):
        calls = []

        def once(url, timeout):
            calls.append(url)
            return None, "", "TimeoutError: timed out"

        status, _, error = check._get_resolving("https://x/", 1.0, once=once, sleep=lambda s: None)
        self.assertIsNone(status)
        self.assertEqual(len(calls), 1)

    def test_is_dns_error(self):
        self.assertTrue(check.is_dns_error("URLError: <urlopen error [Errno -3] Temporary failure in name resolution>"))
        self.assertFalse(check.is_dns_error("HTTP 502"))


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, seconds):
        self.t += seconds


def _getter(script):
    """``script(round_no, url) -> (status, body, error)``; counts rounds by home hits."""
    state = {"round": 0}

    def get(url):
        if url.endswith("/"):
            state["round"] += 1
        return script(state["round"], url)

    return get


def _ok_answer(url):
    if "/api/health/ready" in url:
        return 200, '{"status": "ready"}', ""
    if "/api/listings" in url:
        return 200, '{"items": [{"id": 7}]}', ""
    return 200, "<html>Radar</html>", ""


def _ssl_ok(host, port, timeout=None):
    raise AssertionError("not used")


class ConfirmTests(unittest.TestCase):
    def _run(self, script):
        clock = FakeClock()
        results = check.run_checks_confirmed(
            base_url="https://example.test",
            get=_getter(script),
            sleep=clock.sleep,
            clock=clock,
            connector=lambda *a, **k: None,
            now=NOW,
        )
        return {r.name: r for r in results if r.name != check.SSL_CHECK_NAME}, clock

    def test_short_outage_recovers_without_alert(self):
        # 502 during a ~1 min deploy restart, OK on the 3rd round.
        def script(round_no, url):
            return (502, "Bad Gateway", "") if round_no <= 2 else _ok_answer(url)

        results, clock = self._run(script)
        self.assertTrue(all(r.ok for r in results.values()))
        self.assertLess(clock.t, check.CONFIRM_SECONDS)
        _, action = check.decide({}, list(results.values()), NOW)
        self.assertFalse(action["notify"])

    def test_persistent_outage_confirmed_after_three_minutes(self):
        def script(round_no, url):
            return 502, "Bad Gateway", ""

        results, clock = self._run(script)
        self.assertFalse(results["site_home"].ok)
        self.assertGreaterEqual(clock.t, check.CONFIRM_SECONDS)
        self.assertIn("potwierdzone", results["site_home"].error)
        _, action = check.decide({}, list(results.values()), NOW)
        self.assertEqual(action["kind"], "down")

    def test_healthy_run_does_not_sleep(self):
        results, clock = self._run(lambda round_no, url: _ok_answer(url))
        self.assertTrue(all(r.ok for r in results.values()))
        self.assertEqual(clock.t, 0.0)

    def test_force_fail_skips_confirmation(self):
        clock = FakeClock()
        results = check.run_checks_confirmed(
            base_url="https://example.test",
            force_fail=True,
            get=lambda url: (None, "", "URLError: Name or service not known") if "invalid" in url else _ok_answer(url),
            sleep=clock.sleep,
            clock=clock,
            connector=lambda *a, **k: None,
            now=NOW,
        )
        self.assertFalse(next(r for r in results if r.name == "site_home").ok)
        self.assertEqual(clock.t, 0.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
