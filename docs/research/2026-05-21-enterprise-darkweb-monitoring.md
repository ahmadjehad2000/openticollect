# Research — Enterprise Dark-Web Monitoring, and a Roadmap for openTIcollect

**Date:** 2026-05-21
**Purpose:** Study how enterprise dark-web / threat-intelligence monitoring
platforms work, and turn that into a concrete, prioritised roadmap for
strengthening openTIcollect.

## Method and scope

This research uses **public sources only**: vendor documentation and blogs,
independent analyst comparisons, and **open-source** CTI platforms whose code is
openly licensed and therefore legal to study.

**Explicitly excluded — leaked or proprietary source code.** Obtaining or
incorporating stolen source code from Recorded Future or any commercial vendor
would be copyright and trade-secret infringement and would expose this project
to direct legal liability. It is also unnecessary: the *architecture* of these
platforms is well documented in public, and mature open-source CTI projects
(OpenCTI, MISP) provide legitimate, high-quality reference implementations.

---

## 1. How enterprise dark-web monitoring works

Synthesised from Recorded Future, Bitsight, CrowdStrike, Mandiant and SpyCloud
material (see Sources). The capability stack has five layers.

### 1.1 Collection — breadth and resilience
- **Source breadth.** Recorded Future collects from 250+ top/medium-tier dark-web
  forums plus Tor sites, IRC, marketplaces, shops, paste sites, ransomware leak
  sites and Telegram. Enterprise platforms index *tens of thousands* of onion
  services.
- **Infrastructure tracking.** Criminal communities move IPs and domains
  constantly; collectors track sources *across* those moves rather than treating
  a dead address as a dead source.
- **Safe collection.** Automated collection, data caching and sandboxing gather
  intelligence without exposing analysts to live malicious content.

### 1.2 Analysis and enrichment
- **NLP** translates and analyses sources in every language (deep analysis in
  ~12 languages) — dark-web content is heavily multilingual.
- **ML classification** sifts thousands of posts daily, assigning **risk scores**
  and surfacing which threats are credible, emerging, or industry-specific.
- **Entity / IOC extraction** turns free text into structured indicators.

### 1.3 Correlation
- Dark-web findings are linked to **vulnerability intelligence, threat-actor
  profiles, malware repositories and campaigns**. "A credential leak tied to a
  known APT group has more context than the same leak in isolation."

### 1.4 Targeted exposure detection
- Detect when an org's **brand, executives, vendors or customers** appear in
  leaked datasets, credential dumps or sale forums.
- **Credential / identity intelligence** — deep breach and stealer-log analysis
  with enriched PII (SpyCloud-style botnet/sinkhole telemetry).
- **Supply-chain risk** — monitoring third-party vendor exposure, not just one's
  own.

### 1.5 Output and integration
- Structured output (STIX), structured **APIs**, bulk data feeds, automated
  alerting that slots into **SIEM/SOAR** workflows.
- Success is measured as reduction in **MTTD/MTTR** (mean time to detect/respond).

---

## 2. Legitimate reference implementations

Two open-source CTI platforms are worth studying directly — their code is openly
licensed:

- **OpenCTI** (Filigran, with ANSSI) — built on the **STIX 2.1** data model;
  GraphQL API; a clean **connector taxonomy**: external-input, stream,
  internal-enrichment, import-file, export-file. A good model for structuring
  entities and for a pluggable collector/enrichment design.
- **MISP** — event/attribute sharing, community feeds, correlation across events.
  A good model for indicator sharing and feed ingestion.

openTIcollect should *borrow patterns* from these (STIX-shaped entities, an
enrichment stage, a read API) — not copy code — keeping its single-binary,
no-CGO, minimal-dependency character.

---

## 3. Where openTIcollect stands today

**Strengths**
- 15 collectors spanning clear web, paste sites, breach catalogs, threat feeds,
  Telegram and the dark web (Ahmia + Tor onion fetching).
- Keyword/regex watchlist matching; evidence-backed correlation engine (smart +
  custom rules); per-finding dedup.
- Webhook + email notifiers; full server-rendered UI; editable settings;
  per-source test; scheduler with jitter/backoff; bulk triage; logs page.
- Single static binary, no CGO, minimal dependencies, strict CSP.

**Honest gaps vs enterprise platforms** — see the table below.

---

## 4. Gap analysis

| Capability | Enterprise platforms | openTIcollect today | Gap |
|---|---|---|---|
| Source breadth | 250+ curated forums, 10k+ onion services | Ahmia search + onion watchlist + ~10 TG channels | **Large** — curation & scale |
| Source resilience | Tracks infra across IP/domain moves | Dead sources skipped, logged | Medium — no re-discovery |
| Structured indicators | STIX 2.1 entities, IOC extraction | Flat findings (source/keyword/excerpt) | **Large** |
| Risk scoring | ML-assigned numeric risk | Severity inherited from keyword | Medium |
| Correlation | Links to actors, campaigns, vulns | Keyword-based smart + custom rules | Medium |
| Credential intelligence | Stealer-log parsing, enriched PII | HIBP catalog + Pwned Passwords k-anon | Medium |
| Multilingual | NLP translation, ~12 languages | Literal/regex match only | Medium (scope choice) |
| Integration | STIX/TAXII, SIEM/SOAR, bulk APIs | Webhook + email | **Large** |
| Metrics | MTTD/MTTR dashboards | `source_runs` history, no analytics view | Medium |

---

## 5. Roadmap — prioritised

Each item is grounded in a research finding above and is scoped to openTIcollect's
constraints (Go, minimal deps, single binary). None requires leaked code; none
requires an external AI service unless explicitly noted.

### P1 — high impact, fits the current design

1. **IOC extraction & structured entities.** Parse every finding's excerpt/raw
   for indicators — IPv4/IPv6, domains, URLs, emails, MD5/SHA1/SHA256, CVE IDs,
   Bitcoin/Ethereum addresses. Store them in an `indicators` table linked to the
   finding. *Closes:* "structured indicators" gap. *Builds on:* the existing
   `matcher`/`models` packages. No AI needed.

2. **Computed risk score.** A 0–100 score per finding derived from concrete
   signals: keyword severity, source trust weight, recency, multi-source
   corroboration (from the correlation engine), and number/type of extracted
   IOCs. Sort/filter findings by it. *Closes:* "risk scoring" gap. Deterministic,
   no ML.

3. **Read API + STIX 2.1 export.** `GET /api/findings` (JSON, filterable) and a
   STIX 2.1 bundle export endpoint, so openTIcollect slots into SOC/SIEM
   workflows. *Closes:* "integration" gap. The STIX shape is a documented public
   standard.

### P2 — meaningful, moderate effort

4. **Source curation + health tracking.** Ship a curated default set of
   dark-web / leak sources; track per-source success rate over time; auto-quiet
   sources that fail persistently and surface them on `/sources`. *Closes:*
   source breadth/resilience gaps.

5. **Credential / stealer-log handling.** Detect credential-dump structure
   (`user:pass`, `url:login:pass`, stealer-log layouts) in scraped/paste/Telegram
   content; a dedicated credential finding type with the affected domain
   extracted. *Closes:* "credential intelligence" gap. Pattern-based, no AI.

6. **Cross-source entity correlation.** Extend the correlation engine to
   correlate on *extracted IOCs* (item 1), not only keywords — e.g. an IP seen in
   Feodo + a paste + a Telegram channel is a strong corroborated signal.

7. **Collection analytics view.** A page charting findings over time, per-source
   yield, and time-to-first-detection per keyword — the MTTD proxy.

### P3 — scope decisions (need a deliberate call)

8. **Multilingual matching.** Dark-web content is multilingual; literal matching
   misses non-English mentions. Lightweight options: Unicode normalisation and
   transliteration of keywords. Full NLP translation would need an external
   service — currently out of scope per the project's "no LLM/AI enrichment"
   rule. *Decision needed.*

9. **ML risk classification — DECIDED: not adopted.** Enterprise platforms use
   ML to rank credibility. openTIcollect instead ships a *deterministic,
   explainable* 0–100 risk score (`internal/risk`) that weights severity,
   source trust, recency, extracted-IOC count and leaked-credential count.
   Every point traces to a concrete signal, so an analyst can audit any score
   — an advantage over an opaque model. Adding an ML classifier (and the
   external service or model weights it needs) is **explicitly out of scope**
   per the project's no-AI/no-LLM rule, reaffirmed by the user on 2026-05-21
   ("no need for ML or extra AI"). This item is closed, not deferred.

---

## Recommended next steps

Start with **P1 items 1–3** — IOC extraction, risk scoring, and the read API +
STIX export. Together they move openTIcollect from "flat keyword findings" to
"structured, scored, integrable intelligence", which is the single biggest
qualitative gap versus enterprise platforms — and all three are achievable
within the existing architecture with no new external dependencies.

## Implementation status (2026-05-21)

Roadmap items P1.1–P1.3, P2.4–P2.7 and P3.8 are implemented in the codebase.
P3.9 is closed as a deliberate no-ML decision (above). The platform now
extracts structured indicators and leaked credentials from every finding,
scores each finding deterministically, escalates brand credential leaks,
correlates on shared IOCs, exposes a JSON read API plus STIX 2.1 export, tracks
per-source health, ships curated leak-tracker feeds, renders a collection
analytics page, and folds Unicode homoglyphs/full-width forms when matching.

## Sources

- [Recorded Future — What Is Dark Web Monitoring?](https://www.recordedfuture.com/blog/dark-web-monitoring)
- [Recorded Future — Dark Web Monitoring data sheet](https://go.recordedfuture.com/hubfs/data-sheets/dark-web.pdf)
- [Recorded Future — Improving Dark Web Investigations with Threat Intelligence](https://www.recordedfuture.com/blog/improving-dark-web-investigations-with-threat-intelligence)
- [Bitsight — Advanced Dark Web Intelligence: How to Choose a Provider](https://www.bitsight.com/guides/best-advanced-dark-web-intelligence-providers-how-to-choose)
- [Huntress — Standout Dark Web Monitoring Platforms 2026](https://www.huntress.com/cybersecurity-insights/dark-web-monitoring-platforms-2026)
- [Mandiant Digital Threat Monitoring — Google Cloud](https://cloud.google.com/security/products/digital-threat-monitoring)
- [OpenCTI — GitHub](https://github.com/OpenCTI-Platform/opencti)
- [OpenCTI: open-source cyber threat intelligence platform — Help Net Security](https://www.helpnetsecurity.com/2024/08/21/opencti-open-source-cyber-threat-intelligence-platform/)
- [OpenCTI connectors — MISP connector README](https://github.com/OpenCTI-Platform/connectors/blob/master/external-import/misp/README.md)
