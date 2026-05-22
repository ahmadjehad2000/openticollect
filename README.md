<p align="center">
  <img src="web/static/logo.svg" alt="openTIcollect" width="320">
</p>

openTIcollect is a self-hosted threat-intelligence and leak-monitoring tool.
You give it a watchlist (your domains, brand names, product names, people). It
checks paste sites, breach feeds, threat-intel sources, public Telegram
channels, X, and the dark web for any mention of them, and tells you when
something turns up.

It is one static binary with the web UI built in. No CGO, no database server,
no external services, no front-end build step. Run the binary or the container
and it works.

## What it does

It runs one loop, continuously:

1. **Collect.** 16 collectors pull from clear-web sources, paste sites, breach
   catalogs, threat-intel feeds, Telegram, X, and the dark web.
2. **Match.** Everything fetched is checked against your keyword/regex
   watchlist. Literal keywords match whole words only and fold Unicode
   look-alikes, so a Cyrillic-letter spoof of your brand still matches.
3. **Enrich.** Each match is parsed for indicators (IPs, domains, URLs, emails,
   file hashes, CVEs, crypto addresses) and leaked credentials, then given a
   risk score from 0 to 100. A leaked credential that names a watched asset is
   raised to critical automatically.
4. **Correlate.** The same keyword, or the same indicator, showing up across
   several sources is promoted to a higher-confidence alert.
5. **Notify.** New findings go to a webhook and/or email, gated by severity.

Findings are stored in SQLite, shown in the web console, and available over a
read API (JSON and STIX 2.1).

## Setup

You need Go 1.25 or newer to build it, or just use Docker. There is no database
to install and no API key required to start.

1. Copy the baseline config. It works as-is, and every option is explained
   inline:

   ```sh
   cp .env.backup .env
   ```

2. Start it. Run it directly:

   ```sh
   make run
   ```

   Or run it in Docker. The SQLite database persists in `./data` on the host,
   so it survives restarts and upgrades:

   ```sh
   docker compose up -d                 # app on http://localhost:8080
   docker compose --profile tor up -d   # also starts a Tor proxy
   ```

   The container is a 32 MB Alpine image with a built-in health check. To build
   it yourself: `docker build -t openticollect .`

3. Open http://localhost:8080, go to the **Keywords** page, and add your
   domains, brand names, and product names. Each keyword is a literal or a
   regular expression, with its own severity.

4. As collectors run, anything matching your watchlist lands on the
   **Findings** page, scored and ready to triage.

5. Wire up the optional parts in `.env` when you want them:

   - **Notifications:** set `WEBHOOK_URL` and/or the `SMTP_*` values.
   - **Read API:** set `API_KEY` to turn on `/api/*` and the STIX export.
   - **API-backed collectors:** add `OTX_API_KEY`, `ABUSEIPDB_API_KEY`, and the
     rest to light those sources up.
   - **Dark web:** run the Tor sidecar (above) and set
     `TOR_PROXY=socks5://tor:9050`.

Changes to `.env` apply on the next start. Most settings can also be edited
live on the **Settings** page.

## Sources

| Collector | Monitors | API key |
|---|---|---|
| `otx` | AlienVault OTX subscribed pulses | `OTX_API_KEY` |
| `abuseipdb` | AbuseIPDB blacklist | `ABUSEIPDB_API_KEY` |
| `abusech` | abuse.ch URLhaus, ThreatFox, MalwareBazaar | `ABUSECH_AUTH_KEY` |
| `feodo` | abuse.ch Feodo Tracker botnet C2 list | none |
| `pulsedive` | Pulsedive indicator lookups | `PULSEDIVE_API_KEY` |
| `intelx` | Intelligence X free-tier search | `INTELX_API_KEY` |
| `hibp` | HIBP breach catalog and Pwned Passwords | none |
| `nvd` | NVD CVE feed | optional `NVD_API_KEY` |
| `cisakev` | CISA Known Exploited Vulnerabilities catalog | none |
| `pastes` | Pastebin archive, dpaste, and other paste sites | none |
| `webscraper` | your `WEBSCRAPER_URLS` watchlist (robots-aware) | none |
| `secretscanner` | scans `SECRETSCAN_URLS` for exposed keys/credentials | none |
| `rssfeeds` | `RSS_FEEDS`, with a curated breach/leak default set | none |
| `telegram` | public Telegram channels, with a curated default set | none |
| `x` | X (Twitter) search through a Nitter instance | none |
| `darkweb` | Ahmia search and an `.onion` watchlist, over Tor | none |

A collector that is missing its required configuration is shown as
*misconfigured* on the **Sources** page and skipped. It never blocks the rest
of the app. The Sources page also tracks each collector's recent success rate
and quiets one that fails repeatedly.

## Web console

| Page | Contents |
|---|---|
| Dashboard | KPIs and recent activity |
| Findings | active matches; filter by source, severity, risk; open one for its excerpt, extracted indicators, and any leaked credentials |
| Archive | findings you have reviewed or suppressed |
| Correlation | correlated alerts and your custom correlation rules |
| Analytics | findings over time, per-source yield, indicator mix |
| Sources | each collector's status, health, and next run; test any source on demand |
| Keywords | your watchlist: literal or regex, each with a severity |
| Settings | resolved configuration with secrets masked, editable in place |
| Logs | recent application logs |

Pages are server-rendered with a strict Content-Security-Policy: no inline
scripts or styles, no third-party requests. Set `BASIC_AUTH_USER` and
`BASIC_AUTH_PASS` to put the whole UI behind a password.

## Read API and STIX export

Set `API_KEY` and the `/api/*` endpoints turn on, authenticated with an
`Authorization: Bearer <key>` header:

| Endpoint | Returns |
|---|---|
| `GET /api/findings` | findings as JSON; filter by source, severity, status, `min_risk` |
| `GET /api/findings/{id}` | one finding with its extracted indicators |
| `GET /api/indicators` | extracted indicators; filter by kind or value |
| `GET /api/stix` | a STIX 2.1 bundle of indicators, for SIEM or TIP ingestion |

Without `API_KEY` set the API stays off and the endpoints return `503`.

## Webhook payload

New findings are POSTed as JSON. When `WEBHOOK_SECRET` is set, the request
carries an `X-Webhook-Signature` header, a hex HMAC-SHA256 of the body, so the
receiver can verify it.

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

The smart engine runs with no setup. It raises an alert when a keyword is seen
across 2 or more distinct sources within 24h, when one keyword has an activity
burst, or when the same extracted indicator (an IP, a hash, a domain) appears
across several sources. Custom rules, managed on the Correlation page, let you
set exact thresholds: keyword, minimum sources, minimum count, time window, and
the severity to assign. Correlated alerts appear in Findings under the source
`correlation` and notify like any other finding.

## Configuration

All configuration is environment variables, loaded from `.env`. The full
commented list is in [`.env.backup`](.env.backup). The ones you are most likely
to set:

- `DATABASE_PATH`: SQLite file location (default `./data/openticollect.db`).
- `LISTEN_ADDR`: bind address (default `:8080`).
- `BASIC_AUTH_USER` / `BASIC_AUTH_PASS`: set both to password-protect the UI.
- `API_KEY`: set to enable the read API and STIX export.
- `WEBHOOK_URL` / `WEBHOOK_SECRET`: the webhook notifier.
- `SMTP_*`: the email notifier.
- `TOR_PROXY`: SOCKS5 proxy for the dark-web collector.

The Settings page shows the resolved configuration with every secret masked.

## Project layout

```
cmd/server/      entry point, wiring, graceful shutdown
internal/
  config/        environment loading, validation, secret masking
  store/         SQLite (modernc): schema, migrations, queries
  models/        shared data types
  matcher/       whole-word, Unicode-folding keyword matching
  ioc/           indicator and leaked-credential extraction
  risk/          deterministic 0 to 100 risk scoring
  collectors/    the 16 source collectors
  correlation/   smart, custom, and cross-indicator correlation
  scheduler/     per-collector goroutines, jitter, backoff, enrichment
  notifier/      webhook and email fan-out
  server/        HTTP handlers, middleware, read API, STIX, templates
web/             embedded templates and static assets
```

## Building

```sh
make build      # CGO_ENABLED=0 static binary -> ./openticollect
make lint       # go vet + gofmt check
```

The code is plain Go with a small, fixed dependency set: a pure-Go SQLite
driver, an HTML parser, a dotenv loader, and a SOCKS proxy dialer. No ORM, no
web framework, no front-end toolchain.

## Scope

openTIcollect is a defensive monitoring tool. It reads public sources and free
APIs only. It does not scan, exploit, attack, or log in to anything, and it
does not redistribute the data it observes. It checks whether your watchlist
appears, and reports that to you. There is no ML and no LLM in the pipeline:
the risk score is deterministic, and every point of it is explainable.

## License

Provided as-is for self-hosted defensive use.
