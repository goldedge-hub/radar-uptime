# radar-uptime

Samodzielny, publiczny monitor dostępności **Radar Nieruchomości**
(https://radarnieruchomosci.com). Uruchamiany przez GitHub Actions co 10 minut.
Kod korzysta wyłącznie z biblioteki standardowej Pythona 3 — nie ma żadnych
zależności do instalowania.

## Co sprawdza `check.py`

| Sprawdzenie | Adres / warunek |
| --- | --- |
| `site_home` | `GET /` → HTTP 200 i treść zawiera „Radar” |
| `api_ready` | `GET /api/health/ready` → HTTP 200 i `{"status": "ready"}` |
| `listing_detail` | id najnowszej oferty z `GET /api/listings?page_size=1&sort=created_at&order=desc`, potem `GET /oferta/<id>` → HTTP 200 |
| `ssl_cert` | certyfikat na `radarnieruchomosci.com:443` ważny jeszcze co najmniej 14 dni |

Każde sprawdzenie ma 15 s timeout i jedną ponowną próbę po 20 s. Adres
publiczny `https://radarnieruchomosci.com/api/...` trafia do API dzięki
przepisaniu `/api/:path*` w `apps/web/next.config.ts`.

## Alerty

* Po **2 kolejnych nieudanych przebiegach** wysyłany jest e-mail
  `[Radar] AWARIA strony: <sprawdzenia>`; przy `force_fail` alarm leci od razu.
* Dopóki awaria trwa, przypomnienie wysyłane jest najwyżej **co 3 h**.
* Po powrocie do działania przychodzi jednorazowy e-mail
  `[Radar] OK — strona działa` z czasem niedostępności.
* Ostrzeżenie o wygasającym certyfikacie SSL wysyłane jest najwyżej **raz na 24 h**.

Wysyłka odbywa się przez API Resend (`POST https://api.resend.com/emails`).
Stan monitora (liczba niepowodzeń, znaczniki czasu) trzymany jest w pliku
`uptime-state.json` na gałęzi `state`; commit i push następują tylko wtedy, gdy
stan faktycznie się zmieni. Gałąź `state` tworzona jest automatycznie.

## Sekrety (Settings → Secrets and variables → Actions)

| Sekret | Znaczenie |
| --- | --- |
| `RESEND_API_KEY` | klucz API Resend; bez niego monitor działa, ale nie wysyła maili |
| `ALERT_TO` | odbiorca alertów (można podać kilka adresów po przecinku) |
| `ALERT_FROM` | nadawca, np. `Radar Monitor <alerty@radarnieruchomosci.com>` (opcjonalny) |
| `ALERT_TO_OVERRIDE` | opcjonalny zastępczy odbiorca; nadpisuje `ALERT_TO` |

## Ręczny test

Uruchom workflow z zakładki **Actions → uptime → Run workflow**:

* `force_fail = true` — jedno sprawdzenie celuje w nieistniejący host, więc
  ścieżka awarii (i e-mail `[Radar] AWARIA strony: ...`) jest przećwiczona od razu;
* `alert_to_override = test@example.com` — alert trafi tylko na podany adres.

Lokalnie (bez gita i bez wysyłki maili):

```bash
python3 check.py --dry-run
python3 test_check.py
```
