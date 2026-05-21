# openTIcollect

A self-hosted threat-intelligence collection and leak-monitoring platform. It runs
a set of source collectors, matches everything they fetch against a keyword/regex
watchlist, stores the matches as **findings** in SQLite, and dispatches them to
webhook and email notifiers. It ships as a single static binary with an embedded
web UI — no CGO, no external services, no front-end build step.

## Features

- **12 collectors** across clear web, paste sites, breach catalogs, threat-intel
  feeds, public Telegram channels and the dark web (see the table below).
- **Keyword watchlist** — literal or regex, each with a severity.
- **Findings** stored in SQLite with automatic deduplication.
- **Correlation engine** — a built-in *smart* engine (multi-source corroboration
  and activity-burst detection) plus user-defined *custom* rules, raising
  higher-confidence correlated alerts.
- **Notifiers** — webhook (HMAC-signed) and email, each severity-gated.
- **Web UI** — server-rendered dark security console: dashboard, findings,
  correlation, sources, keywords and settings pages.
- **Hardened** — strict Content-Security-Policy and security headers on every
  response; optional HTTP basic auth.
- **Single static binary** — `CGO_ENABLED=0`, web assets embedded.

## Sources

| Collector | What it monitors | Auth | Works without a key? |
|---|---|---|---|
| `otx` | AlienVault OTX subscribed pulses | `OTX_API_KEY` | no |
| `abuseipdb` | AbuseIPDB blacklist | `ABUSEIPDB_API_KEY` | no |
| `abusech` | URLhaus + ThreatFox + MalwareBazaar | `ABUSECH_AUTH_KEY` | no |
| `pulsedive` | Pulsedive indicator feed | `PULSEDIVE_API_KEY` | no |
| `intelx` | IntelX free-tier search | `INTELX_API_KEY` | no |
| `hibp` | HIBP breach catalog + Pwned Passwords | none | yes |
| `nvd` | NVD CVE 2.0 feed | optional `NVD_API_KEY` | yes |
| `pastes` | Pastebin archive, dpaste | none | yes |
| `webscraper` | `WEBSCRAPER_URLS` watchlist (robots.txt-aware) | none | yes* |
| `rssfeeds` | `RSS_FEEDS` watchlist | none | yes |
| `telegram` | Public channels via `t.me/s/<channel>` | none | yes* |
| `darkweb` | Ahmia search + `.onion` watchlist (via Tor) | none | yes |

\* keyless, but reports itself `misconfigured` until its URL/channel list is set.

A collector whose required environment variable is missing is shown as
`misconfigured` and skipped — **the app boots and runs with zero keys configured.**

## Quick start

```sh
cp .env.example .env      # edit as needed; works as-is with no keys
make run                  # builds and starts the server
```

Open <http://localhost:8080>. Add a keyword on the **Keywords** page; matching
items appear on **Findings** as collectors run.

## Docker

```sh
docker compose up                 # app on :8080, data in ./data
docker compose --profile tor up   # also start a Tor SOCKS5 sidecar
```

With the Tor sidecar running, set `TOR_PROXY=socks5://tor:9050` in `.env` to enable
the `.onion` watchlist.

## Configuration

All configuration is environment variables, loaded from `.env`. See
[`.env.example`](.env.example) for the complete list with comments. Highlights:

- `DATABASE_PATH` — SQLite file location (default `./data/openticollect.db`).
- `BASIC_AUTH_USER` / `BASIC_AUTH_PASS` — if both set, the whole UI requires basic auth.
- `WEBHOOK_URL` / `WEBHOOK_SECRET` / `WEBHOOK_MIN_SEVERITY` — webhook notifier.
- `SMTP_*` / `EMAIL_MIN_SEVERITY` — email notifier.
- Collector keys — omit any to leave that collector `misconfigured`.

The **Settings** page renders the resolved configuration with every secret masked.

## Webhook payload

Findings are `POST`ed as JSON. If `WEBHOOK_SECRET` is set, the request carries
`X-Webhook-Signature: <hex hmac-sha256 of the body>`.

```json
{
  "id": 1234,
  "timestamp": "2026-05-20T10:15:00Z",
  "source": "pastebin",
  "source_url": "https://pastebin.com/abcd1234",
  "matched_keyword": "acme.com",
  "severity": "critical",
  "excerpt": "...emails matching acme.com found...",
  "host": "openticollect.local"
}
```

## Correlation

The **smart engine** runs by default with no configuration: it raises a
correlated alert when a keyword is corroborated by 2 or more distinct sources
within 24h, or when 5 or more findings for one keyword indicate an activity
burst. **Custom rules** (managed on the Correlation page) let you set precise
thresholds — keyword, minimum sources, minimum count, time window and the
severity to assign. Correlated alerts appear in Findings under source
`correlation` and are dispatched to notifiers like any other finding.

## Project layout

```
cmd/server/      entrypoint, wiring, graceful shutdown
internal/
  config/        env loading, validation, secret masking
  store/         SQLite (modernc), schema, queries
  models/        shared data types
  matcher/       literal + regex keyword matching
  collectors/    the 12 source collectors + scheduler input
  correlation/   smart + custom correlation engines
  scheduler/     per-collector goroutines, jitter, backoff, periodic correlation
  notifier/      webhook + email fan-out
  server/        HTTP handlers, middleware, templates
web/             embedded templates and static assets
```

## Development

```sh
make build       # CGO_ENABLED=0 static binary -> ./openticollect
make test        # go test ./...
make lint        # go vet + gofmt check
```

## Security and scope

openTIcollect is a **defensive monitoring** tool. It only reads public sources and
free APIs. It does not perform active scanning, exploitation, or any outbound
attack capability, and it does not interact with login-walled or seized forums. It
integrates only free or free-but-authenticated APIs — no paid tiers.

## License

Provided as-is for self-hosted defensive use.
