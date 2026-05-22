```text
   ┌─────────┐
   │   ◓     │   openTIcollect
   │       · │   ───────────────────────────────────────
   └─────────┘   threat-intelligence collection & leak monitoring
```

> **Watch the places your name could leak — and know the moment it does.**

openTIcollect is a self-hosted threat-intelligence and leak-monitoring platform.
You give it a watchlist — your domains, brand names, product names, executives —
and it continuously checks paste sites, breach feeds, threat-intel sources,
public Telegram channels, X, and the dark web for any mention of them. Every
match becomes a **finding**: stored, scored, enriched with the indicators it
contains, and pushed to your webhook or inbox.

It runs as a **single static binary** with the web UI baked in. No CGO, no
database server, no external services, no front-end build step. Drop the binary
on a box (or run the container) and it works.

---

## What it does

The platform runs one simple loop, continuously:

1. **Collect** — 16 collectors pull from clear-web sources, paste sites, breach
   catalogs, threat-intel feeds, Telegram, X and the dark web.
2. **Match** — everything fetched is checked against your keyword/regex
   watchlist. Literal keywords match whole words only, fold Unicode look-alikes
   (so a Cyrillic-letter spoof of your brand still matches), and never collide
   with one another.
3. **Enrich** — each finding is parsed for structured indicators (IPs, domains,
   URLs, emails, file hashes, CVEs, crypto addresses) and leaked credentials,
   then given a deterministic **0–100 risk score**. A leaked credential that
   names one of your watched assets is escalated to *critical* automatically.
4. **Correlate** — a built-in engine raises higher-confidence alerts when the
   same keyword or the same indicator shows up across multiple sources.
5. **Notify** — new findings go to a webhook and/or email, gated by severity.

Everything is visible in a clean, server-rendered web console, and everything
is queryable through a read API (JSON and STIX 2.1).

---

## Setup

openTIcollect needs nothing but itself to run — there is no database server to
install and no keys to obtain. It builds with Go 1.25+ (or just use Docker).

**1. Get a config file.** Copy the baseline; it works as-is, and every option
is explained inline:

```sh
cp .env.backup .env
```

**2. Start it.** Run it directly:

```sh
make run        # builds the static binary and starts the server on :8080
```

…or run it in Docker — the SQLite database persists in `./data` on the host, so
it survives restarts and upgrades:

```sh
docker compose up -d                 # app on http://localhost:8080
docker compose --profile tor up -d   # also start a Tor proxy for the dark web
```

The container is a ~32 MB Alpine image with a built-in health check. To build
it yourself: `docker build -t openticollect .`

**3. Add what you want to watch.** Open <http://localhost:8080>, go to the
**Keywords** page, and add your domains, brand names and product names. Each
keyword is a literal or a regular expression, with its own severity.

**4. Watch the findings arrive.** As collectors run, anything matching your
watchlist lands on the **Findings** page — scored, enriched with the indicators
it contains, and ready to triage.

**5. Wire up the extras when you need them.** All optional, all in `.env`:

- **Notifications** — set `WEBHOOK_URL` and/or the `SMTP_*` values to have new
  findings pushed to you.
- **Read API** — set `API_KEY` to turn on `/api/*` and the STIX 2.1 export.
- **API-backed collectors** — add `OTX_API_KEY`, `ABUSEIPDB_API_KEY`,
  `PULSEDIVE_API_KEY` and friends to light those sources up.
- **Dark web** — run the Tor sidecar (above) and set
  `TOR_PROXY=socks5://tor:9050` to enable the `.onion` watchlist and Ahmia search.

Changes to `.env` apply on the next start; most settings can also be edited
live on the **Settings** page.

---

## Sources

| Collector | What it monitors | API key |
|---|---|---|
| `otx` | AlienVault OTX subscribed pulses | `OTX_API_KEY` |
| `abuseipdb` | AbuseIPDB blacklist | `ABUSEIPDB_API_KEY` |
| `abusech` | abuse.ch URLhaus + ThreatFox + MalwareBazaar | `ABUSECH_AUTH_KEY` |
| `feodo` | abuse.ch Feodo Tracker botnet C2 list | none |
| `pulsedive` | Pulsedive indicator lookups | `PULSEDIVE_API_KEY` |
| `intelx` | Intelligence X free-tier search | `INTELX_API_KEY` |
| `hibp` | HIBP breach catalog + Pwned Passwords (k-anonymity) | none |
| `nvd` | NVD CVE feed | optional `NVD_API_KEY` |
| `cisakev` | CISA Known Exploited Vulnerabilities catalog | none |
| `pastes` | Pastebin archive, dpaste and other paste sites | none |
| `webscraper` | your `WEBSCRAPER_URLS` watchlist (robots-aware) | none † |
| `secretscanner` | scans `SECRETSCAN_URLS` for exposed keys/credentials | none † |
| `rssfeeds` | `RSS_FEEDS` — ships a curated breach/leak-tracker default | none |
| `telegram` | public channels via `t.me/s/` — curated leak-channel default | none |
| `x` | X (Twitter) search via a Nitter instance | none † |
| `darkweb` | Ahmia search + `.onion` watchlist, over Tor | none |

† Keyless, but stays *misconfigured* until you give it a URL list / channel /
Nitter instance to work with.

A collector that is missing its required configuration is shown as
*misconfigured* on the **Sources** page and skipped — it never blocks the rest
of the app. The Sources page also tracks each collector's recent success rate
and automatically quiets one that fails persistently.

---

## The web console

| Page | What's there |
|---|---|
| **Dashboard** | KPIs and recent activity at a glance |
| **Findings** | active matches — filter by source, severity, risk; sort by risk; open any finding for its excerpt, extracted indicators and any leaked credentials |
| **Archive** | findings you've reviewed or suppressed |
| **Correlation** | correlated alerts, plus your custom correlation rules |
| **Analytics** | findings over time, per-source yield, indicator mix |
| **Sources** | every collector's status, health and next run; test any source on demand |
| **Keywords** | your watchlist — literal or regex, each with a severity |
| **Settings** | resolved configuration with secrets masked; editable in place |
| **Logs** | recent application logs |

Everything is server-rendered with a strict Content-Security-Policy — no inline
scripts or styles, no third-party requests. Optional HTTP basic auth puts the
whole UI behind a password.

---

## Read API & STIX export

Set `API_KEY` in your environment and the `/api/*` endpoints turn on, authed
with `Authorization: Bearer <key>`:

| Endpoint | Returns |
|---|---|
| `GET /api/findings` | findings as JSON — filter by source, severity, status, `min_risk` |
| `GET /api/findings/{id}` | one finding with its extracted indicators |
| `GET /api/indicators` | extracted indicators — filter by kind/value |
| `GET /api/stix` | a **STIX 2.1 bundle** of indicators, for SIEM/TIP ingestion |

Without `API_KEY` set, the API stays off (the endpoints return `503`) — it is
opt-in by design.

## Webhook payload

New findings are `POST`ed as JSON. When `WEBHOOK_SECRET` is set, the request
carries `X-Webhook-Signature: <hex HMAC-SHA256 of the body>` so the receiver can
verify it.

```json
{
  "id": 1234,
  "timestamp": "2026-05-22T10:15:00Z",
  "source": "pastes",
  "source_url": "https://pastebin.com/abcd1234",
  "matched_keyword": "acme.com",
  "severity": "critical",
  "excerpt": "...credentials for acme.com found in this dump...",
  "host": "openticollect.local"
}
```

## Correlation

The **smart engine** runs with no setup. It raises a correlated alert when a
keyword is corroborated across 2+ distinct sources within 24h, when one keyword
sees an activity burst, or when the *same extracted indicator* (an IP, a hash, a
domain) appears across multiple sources. **Custom rules**, managed on the
Correlation page, let you set exact thresholds — keyword, minimum sources,
minimum count, time window, and the severity to assign. Correlated alerts land
in Findings under the source `correlation` and notify like any other finding.

---

## Configuration

All configuration is environment variables, loaded from `.env`.
[`.env.example`](.env.example) is the complete, commented list. The essentials:

- `DATABASE_PATH` — SQLite file location (default `./data/openticollect.db`).
- `LISTEN_ADDR` — bind address (default `:8080`).
- `BASIC_AUTH_USER` / `BASIC_AUTH_PASS` — set both to password-protect the UI.
- `API_KEY` — set to enable the read API and STIX export.
- `WEBHOOK_URL` / `WEBHOOK_SECRET` / `WEBHOOK_MIN_SEVERITY` — webhook notifier.
- `SMTP_*` / `EMAIL_MIN_SEVERITY` — email notifier.
- `TOR_PROXY` — SOCKS5 proxy for the dark-web collector.
- Collector keys — omit any and that collector simply stays *misconfigured*.

The Settings page shows the resolved configuration with every secret masked,
and can edit and persist most of it without touching the file.

## Project layout

```
cmd/server/      entrypoint, wiring, graceful shutdown
internal/
  config/        environment loading, validation, secret masking
  store/         SQLite (modernc) — schema, migrations, queries
  models/        shared data types
  matcher/       whole-word, Unicode-folding keyword matching
  ioc/           indicator + leaked-credential extraction
  risk/          deterministic 0–100 risk scoring
  collectors/    the 16 source collectors
  correlation/   smart + custom + cross-IOC correlation engines
  scheduler/     per-collector goroutines, jitter, backoff, enrichment
  notifier/      webhook + email fan-out
  server/        HTTP handlers, middleware, read API, STIX, templates
web/             embedded templates and static assets
```

## Development

```sh
make build       # CGO_ENABLED=0 static binary -> ./openticollect
make test        # go test ./...
make lint        # go vet + gofmt check
```

The codebase is plain Go with a small, fixed dependency set (pure-Go SQLite,
an HTML parser, a dotenv loader, a SOCKS proxy dialer) — no ORM, no web
framework, no front-end toolchain.

## Security & scope

openTIcollect is a **defensive monitoring** tool. It only reads public sources
and free APIs. It does not scan, exploit, attack, or log in to anything, and it
does not redistribute the data it observes — it checks whether *your* watchlist
shows up, and reports that to *you*. There is no ML and no LLM in the pipeline:
the risk score is deterministic and every point of it is explainable.

Monitoring leak channels and breach feeds for your own assets is standard
defensive practice. Use it on assets you are responsible for.

## License

Provided as-is for self-hosted defensive use.
