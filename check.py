#!/usr/bin/env python3
"""Monitor dostępności serwisu Radar Nieruchomości (GitHub Actions).

Uruchamiany z ``.github/workflows/uptime.yml`` co 10 minut. Wykonuje cztery
sprawdzenia (strona główna, ``/api/health/ready``, najnowsza oferta oraz
ważność certyfikatu SSL), a następnie przepuszcza wyniki przez *czysty*
automat stanów (:func:`decide`), który decyduje o wysłaniu alarmu e-mail przez
API Resend.

Stan monitora (liczba kolejnych niepowodzeń, znaczniki czasowe) trzymany jest
w pliku ``uptime-state.json`` na dedykowanej gałęzi ``state``. Zapis następuje
tylko wtedy, gdy stan faktycznie się zmieni: przejście w awarię, przypomnienie,
powrót do działania albo ostrzeżenie o certyfikacie SSL.

Cała logika decyzyjna jest wydzielona do funkcji bez efektów ubocznych, dzięki
czemu ``test_check.py`` może ją przetestować bez sieci. Efekty uboczne (HTTP,
git, e-mail) są zamknięte w osobnych funkcjach.

Moduł korzysta wyłącznie z biblioteki standardowej Pythona 3.
"""

from __future__ import annotations

import argparse
import html
import json
import logging
import os
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse

log = logging.getLogger("radar-uptime")

# ---------------------------------------------------------------------------
# Konfiguracja
# ---------------------------------------------------------------------------

SITE_URL_DEFAULT = "https://radarnieruchomosci.com"
HEALTH_PATH = "/api/health/ready"
# Kolejność zgodna z API: sort=created_at&order=desc zwraca najnowszą ofertę.
LISTINGS_PATH = "/api/listings?page_size=1&sort=created_at&order=desc"
DETAIL_PATH_TEMPLATE = "/oferta/{id}"

SSL_HOST_DEFAULT = "radarnieruchomosci.com"
SSL_PORT = 443
SSL_MIN_DAYS = 14

#: Każde sprawdzenie: 15 s timeout i jedna ponowna próba po 20 s.
HTTP_TIMEOUT = 15.0
HTTP_RETRIES = 1
HTTP_RETRY_DELAY = 20.0
USER_AGENT = "RadarUptime/1.0"

#: Dwa kolejne nieudane przebiegi uruchamiają alarm; przypomnienie co 3 h.
FAIL_THRESHOLD = 2
REMINDER_SECONDS = 3 * 3600
#: Ostrzeżenie o wygasającym certyfikacie najwyżej raz na dobę.
SSL_WARN_SECONDS = 24 * 3600

STATE_VERSION = 1
STATE_BRANCH = "state"
STATE_FILE = "uptime-state.json"

#: ``force_fail`` podmienia adres jednego sprawdzenia na nieistniejący host
#: zarezerwowanej domeny ``.invalid`` (RFC 2606), żeby przećwiczyć ścieżkę awarii.
FORCE_FAIL_URL = "https://uptime-monitor-force-fail.invalid/"

SSL_CHECK_NAME = "ssl_cert"
CHECK_LABELS = {
    "site_home": "strona główna",
    "api_ready": "API /health/ready",
    "listing_detail": "oferta (najnowsza)",
    "ssl_cert": "certyfikat SSL",
}
CHECK_ORDER = ("site_home", "api_ready", "listing_detail", "ssl_cert")

RESEND_ENDPOINT = "https://api.resend.com/emails"
DEFAULT_ALERT_FROM = "Radar Monitor <alerty@radarnieruchomosci.com>"


# ---------------------------------------------------------------------------
# Wynik pojedynczego sprawdzenia
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CheckResult:
    """Wynik jednego sprawdzenia."""

    name: str
    ok: bool
    status: int | None = None
    latency_ms: int = 0
    error: str = ""
    ssl_days: int | None = None

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "ok": self.ok,
            "status": self.status,
            "latency_ms": self.latency_ms,
            "error": self.error,
            "ssl_days": self.ssl_days,
        }


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


def _http_get_once(url: str, timeout: float) -> tuple[int | None, str, str]:
    """Jedna próba GET. Zwraca ``(status, body, error)``.

    Błąd transportu daje ``status=None``; odpowiedź HTTP (także 4xx/5xx) jest
    zwracana jako kod, a nie wyjątek.
    """
    request = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(500_000).decode("utf-8", "replace")
            return int(getattr(response, "status", 0) or 0), body, ""
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(500_000).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001 - treść jest tylko dodatkiem
            body = ""
        return int(exc.code), body, ""
    except Exception as exc:  # noqa: BLE001 - timeout/DNS/TLS itd.
        return None, "", f"{type(exc).__name__}: {exc}"


def http_get(
    url: str,
    *,
    timeout: float = HTTP_TIMEOUT,
    retries: int = HTTP_RETRIES,
    retry_delay: float = HTTP_RETRY_DELAY,
) -> tuple[int | None, str, str]:
    """GET z ponowieniem. Nieudane próby (transport lub nie-2xx) powtarzamy.

    Zwraca ``(status, body, error)``; ``status`` jest ``None``, gdy wszystkie
    próby zakończyły się błędem transportu.
    """
    attempts = max(int(retries), 0) + 1
    status: int | None = None
    body = ""
    error = ""
    for attempt in range(attempts):
        status, body, error = _http_get_once(url, timeout)
        if status is not None and 200 <= status < 300:
            return status, body, ""
        if attempt < attempts - 1:
            time.sleep(retry_delay)
    return status, body, error


def _elapsed_ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)


# ---------------------------------------------------------------------------
# Cztery sprawdzenia
# ---------------------------------------------------------------------------


def check_home(get=http_get, base_url: str = SITE_URL_DEFAULT, *, force_fail: bool = False) -> CheckResult:
    """Strona główna: HTTP 200 i treść zawierająca napis ``Radar``."""
    url = FORCE_FAIL_URL if force_fail else base_url.rstrip("/") + "/"
    started = time.perf_counter()
    status, body, error = get(url)
    latency = _elapsed_ms(started)
    if status is None:
        return CheckResult("site_home", False, None, latency, error or "błąd połączenia")
    if status != 200:
        return CheckResult("site_home", False, status, latency, f"HTTP {status}")
    if "Radar" not in body:
        return CheckResult("site_home", False, status, latency, "w HTML brakuje napisu 'Radar'")
    return CheckResult("site_home", True, status, latency, "")


def check_ready(get=http_get, base_url: str = SITE_URL_DEFAULT) -> CheckResult:
    """Publiczny readiness: HTTP 200 i JSON ``status == "ready"``."""
    url = base_url.rstrip("/") + HEALTH_PATH
    started = time.perf_counter()
    status, body, error = get(url)
    latency = _elapsed_ms(started)
    if status is None:
        return CheckResult("api_ready", False, None, latency, error or "błąd połączenia")
    if status != 200:
        return CheckResult("api_ready", False, status, latency, f"HTTP {status}")
    try:
        payload = json.loads(body)
    except ValueError:
        return CheckResult("api_ready", False, status, latency, "odpowiedź nie jest poprawnym JSON-em")
    if not isinstance(payload, dict):
        return CheckResult("api_ready", False, status, latency, "odpowiedź JSON nie jest obiektem")
    if payload.get("status") != "ready":
        return CheckResult(
            "api_ready",
            False,
            status,
            latency,
            f"status={payload.get('status')!r} (oczekiwano 'ready')",
        )
    return CheckResult("api_ready", True, status, latency, "")


def _extract_newest_listing_id(body: str) -> int | None:
    try:
        payload = json.loads(body)
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    items = payload.get("items")
    if not isinstance(items, list) or not items:
        return None
    first = items[0]
    if not isinstance(first, dict):
        return None
    try:
        return int(first.get("id"))
    except (TypeError, ValueError):
        return None


def check_listing(get=http_get, base_url: str = SITE_URL_DEFAULT) -> CheckResult:
    """Najnowsza oferta: pobierz id z API, potem sprawdź ``/oferta/<id>``."""
    base = base_url.rstrip("/")
    started = time.perf_counter()
    status, body, error = get(base + LISTINGS_PATH)
    if status is None:
        return CheckResult("listing_detail", False, None, _elapsed_ms(started), error or "błąd połączenia")
    if status != 200:
        return CheckResult("listing_detail", False, status, _elapsed_ms(started), f"HTTP {status} dla /api/listings")
    listing_id = _extract_newest_listing_id(body)
    if listing_id is None:
        return CheckResult(
            "listing_detail",
            False,
            status,
            _elapsed_ms(started),
            "brak items[].id w odpowiedzi /api/listings",
        )
    detail_url = base + DETAIL_PATH_TEMPLATE.format(id=listing_id)
    detail_status, _body, detail_error = get(detail_url)
    latency = _elapsed_ms(started)
    if detail_status is None:
        return CheckResult("listing_detail", False, None, latency, detail_error or "błąd połączenia")
    if detail_status != 200:
        return CheckResult(
            "listing_detail",
            False,
            detail_status,
            latency,
            f"HTTP {detail_status} dla /oferta/{listing_id}",
        )
    return CheckResult("listing_detail", True, detail_status, latency, "")


def _fetch_cert_not_after(host: str, port: int, *, connector=None) -> str:
    context = ssl.create_default_context()
    connect = connector or socket.create_connection
    with connect((host, port), timeout=HTTP_TIMEOUT) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
    not_after = cert.get("notAfter") if isinstance(cert, dict) else None
    if not not_after:
        raise ValueError("brak pola notAfter w certyfikacie")
    return not_after


def _cert_expiry_epoch(not_after: str) -> float:
    """Zamień datę ``notAfter`` na epoch (z awaryjnym parserem)."""
    try:
        return float(ssl.cert_time_to_seconds(not_after))
    except Exception:  # noqa: BLE001 - np. brak funkcji w przyszłym Pythonie
        pass
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            parsed = datetime.strptime(not_after, fmt)
            return parsed.replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    raise ValueError(f"nierozpoznana data certyfikatu: {not_after!r}")


def check_ssl(
    host: str = SSL_HOST_DEFAULT,
    port: int = SSL_PORT,
    *,
    min_days: int = SSL_MIN_DAYS,
    now: datetime | None = None,
    connector=None,
) -> CheckResult:
    """Ważność certyfikatu SSL: porażka, gdy zostało mniej niż ``min_days``."""
    started = time.perf_counter()
    moment = now or datetime.now(timezone.utc)
    try:
        not_after = _fetch_cert_not_after(host, port, connector=connector)
        days = (_cert_expiry_epoch(not_after) - _as_aware(moment).timestamp()) / 86400.0
    except Exception as exc:  # noqa: BLE001 - każde niedostępne TLS to porażka
        return CheckResult(
            SSL_CHECK_NAME,
            False,
            None,
            _elapsed_ms(started),
            f"błąd sprawdzenia certyfikatu: {type(exc).__name__}: {exc}",
        )
    latency = _elapsed_ms(started)
    whole_days = max(int(days), 0)
    if days < min_days:
        return CheckResult(
            SSL_CHECK_NAME,
            False,
            None,
            latency,
            f"certyfikat SSL wygasa za {days:.1f} dni (próg {min_days} dni)",
            ssl_days=whole_days,
        )
    return CheckResult(SSL_CHECK_NAME, True, None, latency, "", ssl_days=whole_days)


def run_checks(
    *,
    base_url: str = SITE_URL_DEFAULT,
    ssl_host: str = SSL_HOST_DEFAULT,
    ssl_port: int = SSL_PORT,
    force_fail: bool = False,
    get=http_get,
    connector=None,
    now: datetime | None = None,
) -> list[CheckResult]:
    """Uruchom wszystkie sprawdzenia; pojedynczy błąd nie przerywa resztę."""
    jobs = (
        ("site_home", lambda: check_home(get, base_url, force_fail=force_fail)),
        ("api_ready", lambda: check_ready(get, base_url)),
        ("listing_detail", lambda: check_listing(get, base_url)),
        ("ssl_cert", lambda: check_ssl(ssl_host, ssl_port, now=now, connector=connector)),
    )
    results: list[CheckResult] = []
    for name, job in jobs:
        try:
            results.append(job())
        except Exception as exc:  # noqa: BLE001 - monitor nie może się wywrócić
            results.append(
                CheckResult(name, False, None, 0, f"nieoczekiwany błąd: {type(exc).__name__}: {exc}")
            )
    return results


# ---------------------------------------------------------------------------
# Automat stanów (czyste funkcje — testowalne bez sieci)
# ---------------------------------------------------------------------------


def _as_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_aware(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def _iso(moment: datetime) -> str:
    return _as_aware(moment).replace(microsecond=0).isoformat()


def _parse_dt(value) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return _as_aware(parsed)


def _normalize(state: dict | None) -> dict:
    """Sprowadź stan do znanego zestawu kluczy (stabilne porównywanie)."""
    state = state or {}
    return {
        "version": STATE_VERSION,
        "status": str(state.get("status") or "up"),
        "consecutive_failures": _as_int(state.get("consecutive_failures"), 0),
        "down_since": state.get("down_since"),
        "last_down_notified_at": state.get("last_down_notified_at"),
        "last_ssl_warn_at": state.get("last_ssl_warn_at"),
    }


def decide(
    state: dict | None,
    results: list[CheckResult],
    now: datetime,
    *,
    force_fail: bool = False,
    fail_threshold: int = FAIL_THRESHOLD,
    reminder_seconds: int = REMINDER_SECONDS,
    ssl_warn_seconds: int = SSL_WARN_SECONDS,
) -> tuple[dict, dict]:
    """Złóż wyniki w stan i zwróć ``(nowy_stan, akcja)``.

    Sprawdzenia HTTP (poza certyfikatem SSL) tworzą jeden wspólny stan
    „strona działa / nie działa”. Certyfikat SSL ma osobny, dobowy cooldown,
    żeby bliskie wygaśnięcie nie generowało przypomnień co 3 h.

    ``akcja`` to słownik z polami: ``kind`` (``none``/``down``/``reminder``/
    ``recovery``), ``notify``, ``ssl_warning``, ``failed`` (nazwy sprawdzeń),
    ``downtime_seconds``, ``checks`` oraz ``state_changed``.
    """
    now = _as_aware(now)
    old = _normalize(state)
    new = dict(old)

    site_results = [r for r in results if r.name != SSL_CHECK_NAME]
    ssl_result = next((r for r in results if r.name == SSL_CHECK_NAME), None)
    failed_site = [r for r in site_results if not r.ok]

    action = {
        "kind": "none",
        "notify": False,
        "ssl_warning": False,
        "failed": [r.name for r in failed_site],
        "downtime_seconds": None,
        "checks": list(results),
    }

    if not failed_site:
        if old["status"] == "down":
            down_since = _parse_dt(old.get("down_since"))
            downtime = (
                int(max((now - down_since).total_seconds(), 0.0)) if down_since else 0
            )
            action["kind"] = "recovery"
            action["notify"] = True
            action["downtime_seconds"] = downtime
        new["status"] = "up"
        new["consecutive_failures"] = 0
        new["down_since"] = None
        new["last_down_notified_at"] = None
    else:
        threshold = 1 if force_fail else max(int(fail_threshold), 1)
        if old["status"] == "down":
            # Już trwa awaria: nie zwiększamy licznika (mniej commitów stanu co
            # 10 min), a o przypomnieniu decyduje wyłącznie czas.
            last = _parse_dt(old.get("last_down_notified_at"))
            if last is None or (now - last).total_seconds() >= reminder_seconds:
                new["last_down_notified_at"] = _iso(now)
                action["kind"] = "reminder"
                action["notify"] = True
        else:
            failures = old["consecutive_failures"] + 1
            new["consecutive_failures"] = failures
            if failures >= threshold:
                new["status"] = "down"
                new["down_since"] = _iso(now)
                new["last_down_notified_at"] = _iso(now)
                action["kind"] = "down"
                action["notify"] = True

    if ssl_result is not None and not ssl_result.ok:
        last_ssl = _parse_dt(old.get("last_ssl_warn_at"))
        if last_ssl is None or (now - last_ssl).total_seconds() >= ssl_warn_seconds:
            action["ssl_warning"] = True
            new["last_ssl_warn_at"] = _iso(now)

    new["version"] = STATE_VERSION
    action["state_changed"] = new != old
    return new, action


# ---------------------------------------------------------------------------
# Treść i wysyłka e-maila (Resend)
# ---------------------------------------------------------------------------


def _label(name: str) -> str:
    return CHECK_LABELS.get(name, name)


def format_result_line(result: CheckResult) -> str:
    state = "OK" if result.ok else "FAIL"
    if result.name == SSL_CHECK_NAME and result.ssl_days is not None:
        line = f"[{state}] {_label(result.name)} — {result.ssl_days} dni do wygaśnięcia"
    else:
        code = result.status if result.status is not None else "-"
        line = f"[{state}] {_label(result.name)} — HTTP {code}, {result.latency_ms} ms"
    if result.error:
        line += f" — {result.error}"
    return line


def _format_duration(seconds: int) -> str:
    seconds = max(int(seconds), 0)
    hours, rem = divmod(seconds, 3600)
    minutes = rem // 60
    if hours and minutes:
        return f"{hours} godz. {minutes} min"
    if hours:
        return f"{hours} godz."
    return f"{minutes} min"


def build_subject(action: dict) -> str:
    kind = action.get("kind")
    if kind in ("down", "reminder"):
        failed = action.get("failed") or []
        checks = ", ".join(_label(name) for name in failed) or "strona"
        return f"[Radar] AWARIA strony: {checks}"
    if kind == "recovery":
        return "[Radar] OK — strona działa"
    return "[Radar] Uwaga: certyfikat SSL wygasa"


def _intro(action: dict, *, ssl_only: bool) -> str:
    if ssl_only:
        return "Monitor dostępności Radar Nieruchomości — ostrzeżenie o certyfikacie SSL."
    kind = action.get("kind")
    if kind == "down":
        return "Monitor dostępności Radar Nieruchomości — wykryto awarię strony."
    if kind == "reminder":
        return "Monitor dostępności Radar Nieruchomości — strona nadal nie działa."
    if kind == "recovery":
        return "Monitor dostępności Radar Nieruchomości — strona wróciła do działania."
    return "Monitor dostępności Radar Nieruchomości."


def build_body(action: dict, results: list[CheckResult], now: datetime, *, ssl_only: bool = False) -> str:
    moment = _as_aware(now).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [_intro(action, ssl_only=ssl_only), "", f"Data: {moment}"]
    if action.get("downtime_seconds") is not None and not ssl_only:
        lines.append(f"Czas niedostępności: {_format_duration(action['downtime_seconds'])}")
    lines += ["", "Sprawdzenia:"]
    for result in results:
        lines.append(f"  {format_result_line(result)}")
    lines += ["", "--", "Automatyczny monitor: goldedge-hub/radar-uptime"]
    return "\n".join(lines)


def build_html(action: dict, results: list[CheckResult], now: datetime, *, ssl_only: bool = False) -> str:
    moment = html.escape(_as_aware(now).strftime("%Y-%m-%d %H:%M:%S UTC"))
    items = "".join(f"<li>{html.escape(format_result_line(r))}</li>" for r in results)
    extras = ""
    if action.get("downtime_seconds") is not None and not ssl_only:
        extras = f"<p>Czas niedostępności: {html.escape(_format_duration(action['downtime_seconds']))}</p>"
    return (
        "<html><body>"
        f"<p>{html.escape(_intro(action, ssl_only=ssl_only))}</p>"
        f"<p>Data: {moment}</p>{extras}"
        f"<ul>{items}</ul>"
        "<p>—<br>Automatyczny monitor: goldedge-hub/radar-uptime</p>"
        "</body></html>"
    )


def build_mail(
    action: dict, results: list[CheckResult], now: datetime, *, ssl_only: bool = False
) -> tuple[str, str, str]:
    subject = "[Radar] Uwaga: certyfikat SSL wygasa" if ssl_only else build_subject(action)
    text = build_body(action, results, now, ssl_only=ssl_only)
    html_body = build_html(action, results, now, ssl_only=ssl_only)
    return subject, text, html_body


def parse_recipients(raw: str | None) -> list[str]:
    if not raw:
        return []
    recipients: list[str] = []
    for chunk in raw.replace(";", ",").split(","):
        chunk = chunk.strip()
        if chunk:
            recipients.append(chunk)
    return recipients


def _post_resend(data: bytes, api_key: str) -> int:
    request = urllib.request.Request(
        RESEND_ENDPOINT,
        data=data,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            # Resend sits behind Cloudflare, which rejects the default
            # "Python-urllib" User-Agent with 403 (error code 1010).
            "User-Agent": "radar-uptime-monitor/1.0",
        },
    )
    with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
        payload = response.read(100_000)
        try:
            log.info("Resend przyjął e-mail, id=%s.", json.loads(payload or b"{}").get("id"))
        except ValueError:
            pass
        return int(getattr(response, "status", 0) or 0)


def send_mail(
    *,
    api_key: str | None,
    sender: str,
    recipients: list[str],
    subject: str,
    text: str,
    html_body: str | None,
    poster=None,
    bcc: list[str] | None = None,
) -> bool:
    """Wyślij jedną wiadomość. Brak konfiguracji to log, nie wyjątek."""
    if not api_key:
        log.warning("Brak RESEND_API_KEY — pomijam wysyłkę e-maila (%s).", subject)
        return False
    if not recipients:
        log.warning("Brak odbiorcy alertu (ALERT_TO/ALERT_TO_OVERRIDE) — pomijam e-mail (%s).", subject)
        return False
    payload = {"from": sender, "to": recipients, "subject": subject, "text": text}
    if html_body:
        payload["html"] = html_body
    bcc = [addr for addr in (bcc or []) if addr.lower() not in {r.lower() for r in recipients}]
    if bcc:
        payload["bcc"] = bcc
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    post = poster or _post_resend
    try:
        status = post(data, api_key)
    except Exception as exc:  # noqa: BLE001 - nieudany mail nie może przerwać monitora
        log.error("Wysyłka e-maila nie powiodła się: %s: %s", type(exc).__name__, exc)
        return False
    if status is not None and 200 <= status < 300:
        log.info("Wysłano e-mail: %s", subject)
        return True
    log.error("Resend zwrócił status %s (%s).", status, subject)
    return False


def deliver_mails(
    action: dict,
    results: list[CheckResult],
    now: datetime,
    *,
    env=None,
    poster=None,
) -> None:
    """Wyślij ewentualne maile: awarię/powrót oraz ostrzeżenie SSL."""
    env = env if env is not None else os.environ
    api_key = env.get("RESEND_API_KEY")
    sender = env.get("ALERT_FROM") or DEFAULT_ALERT_FROM
    recipients = parse_recipients(env.get("ALERT_TO_OVERRIDE") or env.get("ALERT_TO"))
    # Kopia alertów (BCC, np. dla agenta ops). Przy ręcznym ALERT_TO_OVERRIDE
    # (test) kopii nie dokładamy — mail idzie tylko pod wskazany adres.
    bcc = [] if env.get("ALERT_TO_OVERRIDE") else parse_recipients(env.get("ALERT_BCC"))
    if action.get("notify"):
        subject, text, html_body = build_mail(action, results, now)
        send_mail(
            api_key=api_key,
            sender=sender,
            recipients=recipients,
            subject=subject,
            text=text,
            html_body=html_body,
            poster=poster,
            bcc=bcc,
        )
    if action.get("ssl_warning"):
        subject, text, html_body = build_mail(action, results, now, ssl_only=True)
        send_mail(
            api_key=api_key,
            sender=sender,
            recipients=recipients,
            subject=subject,
            text=text,
            html_body=html_body,
            poster=poster,
            bcc=bcc,
        )


# ---------------------------------------------------------------------------
# Stan na gałęzi ``state``
# ---------------------------------------------------------------------------


def _run_git(args: list[str], *, repo_dir: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], cwd=repo_dir, capture_output=True, text=True, check=False
    )


def fetch_state(*, repo_dir: str = ".") -> tuple[dict, bool]:
    """Wczytaj stan z gałęzi ``state``. Zwraca ``(stan, czy_gałąź_istnieje)``."""
    fetch = _run_git(["fetch", "origin", STATE_BRANCH], repo_dir=repo_dir)
    if fetch.returncode != 0:
        log.info("Gałąź '%s' jeszcze nie istnieje — zaczynam od pustego stanu.", STATE_BRANCH)
        return {}, False
    show = _run_git(["show", f"FETCH_HEAD:{STATE_FILE}"], repo_dir=repo_dir)
    if show.returncode != 0:
        log.info("Gałąź '%s' nie zawiera %s — pusty stan.", STATE_BRANCH, STATE_FILE)
        return {}, True
    try:
        payload = json.loads(show.stdout)
    except ValueError:
        log.warning("Stan na gałęzi '%s' nie jest poprawnym JSON-em — pusty stan.", STATE_BRANCH)
        return {}, True
    return (payload if isinstance(payload, dict) else {}), True


def save_state(state: dict, *, repo_dir: str = ".", branch_exists: bool = False) -> bool:
    """Zapisz stan na gałęzi ``state`` (commit + push). Tworzy gałąź, gdy brak."""
    payload = json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    path = os.path.join(repo_dir, STATE_FILE)
    try:
        if branch_exists:
            checkout = _run_git(["checkout", "-B", STATE_BRANCH, "FETCH_HEAD"], repo_dir=repo_dir)
        else:
            checkout = _run_git(["checkout", "--orphan", STATE_BRANCH], repo_dir=repo_dir)
            if checkout.returncode == 0:
                # Orphan zachowuje indeks/working tree — czyścimy indeks, żeby
                # w gałęzi stanu znalazł się wyłącznie plik stanu.
                _run_git(["rm", "-rf", "--cached", "."], repo_dir=repo_dir)
        if checkout.returncode != 0:
            log.error("git checkout '%s' nie powiódł się: %s", STATE_BRANCH, checkout.stderr.strip())
            return False
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(payload)
        add = _run_git(["add", "-f", STATE_FILE], repo_dir=repo_dir)
        if add.returncode != 0:
            log.error("git add nie powiódł się: %s", add.stderr.strip())
            return False
        message = f"uptime state {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}"
        commit = _run_git(
            [
                "-c",
                "user.name=radar-uptime",
                "-c",
                "user.email=uptime@radarnieruchomosci.com",
                "commit",
                "-m",
                message,
            ],
            repo_dir=repo_dir,
        )
        if commit.returncode != 0:
            log.error("git commit nie powiódł się: %s", commit.stderr.strip())
            return False
        push = _run_git(["push", "origin", f"HEAD:refs/heads/{STATE_BRANCH}"], repo_dir=repo_dir)
        if push.returncode != 0:
            log.error("git push nie powiódł się: %s", push.stderr.strip())
            return False
        log.info("Zapisano stan na gałęzi '%s'.", STATE_BRANCH)
        return True
    except Exception as exc:  # noqa: BLE001 - zapis stanu nie może wywrócić monitora
        log.error("Zapis stanu nie powiódł się: %s: %s", type(exc).__name__, exc)
        return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="check.py",
        description="Monitor dostępności Radar Nieruchomości.",
    )
    parser.add_argument("--base-url", default=None, help="adres bazowy (domyślnie SITE_URL)")
    parser.add_argument("--repo-dir", default=None, help="katalog repozytorium git ze stanem")
    parser.add_argument("--force-fail", action="store_true", help="test ścieżki awarii")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="wykonaj sprawdzenia, ale nie ruszaj git-a ani nie wysyłaj maili",
    )
    parser.add_argument(
        "--exit-on-failure",
        action="store_true",
        help="zwróć kod 1, gdy którekolwiek sprawdzenie zawiedzie",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if log.handlers == []:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    base_url = (args.base_url or os.environ.get("SITE_URL") or SITE_URL_DEFAULT).rstrip("/")
    ssl_host = os.environ.get("SSL_HOST") or urlparse(base_url).hostname or SSL_HOST_DEFAULT
    force_fail = bool(args.force_fail) or _env_bool("FORCE_FAIL")
    now = datetime.now(timezone.utc)

    log.info("Start monitora: %s (force_fail=%s).", base_url, force_fail)
    results = run_checks(base_url=base_url, ssl_host=ssl_host, force_fail=force_fail, now=now)
    for result in results:
        log.info("%s", format_result_line(result))

    repo_dir = args.repo_dir or os.path.dirname(os.path.abspath(__file__))
    state: dict = {}
    branch_exists = False
    if not args.dry_run:
        try:
            state, branch_exists = fetch_state(repo_dir=repo_dir)
        except Exception as exc:  # noqa: BLE001
            log.error("Odczyt stanu nie powiódł się: %s: %s", type(exc).__name__, exc)
            state, branch_exists = {}, False

    new_state, action = decide(state, results, now, force_fail=force_fail)
    log.info(
        "Decyzja: kind=%s notify=%s ssl_warning=%s zmiana_stanu=%s.",
        action["kind"],
        action["notify"],
        action["ssl_warning"],
        action["state_changed"],
    )

    if args.dry_run:
        log.info("Dry-run: pomijam git i wysyłkę maili.")
    else:
        try:
            deliver_mails(action, results, now)
        except Exception as exc:  # noqa: BLE001
            log.error("Obsługa maili nie powiodła się: %s: %s", type(exc).__name__, exc)
        if force_fail:
            # A forced test must never touch the real state, otherwise the next
            # scheduled run would send a bogus "przywrócone" mail.
            log.info("force_fail: test izolowany — nie zapisuję stanu.")
        elif action["state_changed"]:
            save_state(new_state, repo_dir=repo_dir, branch_exists=branch_exists)
        else:
            log.info("Stan bez zmian — nie zapisuję gałęzi '%s'.", STATE_BRANCH)

    if args.exit_on_failure and not all(result.ok for result in results):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
