# EVVP — Early Vulnerability & Vulnerability Intelligence Platform

An automated vulnerability-intelligence and early-warning platform:

**Collect → Normalize → Detect → Enrich → Correlate → Prioritize → Alert → Verify → Continuously update**

EVVP watches NVD, CISA KEV, GitHub, Reddit and any RSS/Atom or JSON-API security source you approve, detects security signals, links
reports about the same vulnerability across sources, enriches CVEs with NVD / EPSS / CISA KEV, scores risk with a
fully explained breakdown, flags *potential* zero-day candidates, and presents everything in an analyst dashboard.

```
 NVD · GitHub · Reddit · RSS/Atom (Source Manager)          source trust: authoritative … early_signal
                         │
                 INGESTION (per-source interval, health, back-off, SSRF guard)
                         │
        signal filter → CVE extraction → NVD / EPSS / CISA-KEV enrichment → novelty & dedupe
                         │                       (every stage fails open; the CVE id is never lost)
                 STORAGE (JSONL files, or PostgreSQL)
                         │
   ENTITY ENGINE: one finding per vulnerability, evidence from many sources, timeline, lead time
                         │
   risk breakdown · zero-day candidate · MITRE ATT&CK · trending · threat landscape · analyst status
                         │
                  REST API (/api)  ──►  analyst dashboard (served at /)
```

## Quick start

Requires Python 3.10+. No Node, no database, no API keys are needed.

```bash
./start.sh                       # creates a virtualenv, installs deps, starts collectors + API + dashboard
# open http://127.0.0.1:8000
```

Manual equivalent:

```bash
cd evvp-backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt            # core: flask, requests, python-dotenv, feedparser
# pip install -r requirements-optional.txt # only for PostgreSQL (psycopg2-binary) or AI summaries (openai)
cp .env.example .env             # optional; every value may stay empty
python main.py                   # collectors + API + dashboard
```

| Command | What it does |
|---|---|
| `python main.py` | everything: collectors, API, dashboard (http://127.0.0.1:8000) |
| `python main.py --api-only` | dashboard + API over already-collected data |
| `python main.py --ingest-only` | collectors only |
| `python main.py --once` | one pass over every enabled source, then exit |
| `python main.py --once --collector blog` | one pass of one collector (`blog`, `github`, `nvd`, `cisa`, `reddit`) |

The repository ships with 138 evidence items that were collected from live sources on 2026-09-03 (`evvp-backend/raw_data/`), so the dashboard is populated on first start. To start empty, point `EVVP_RAW_DATA_DIR` / `EVVP_DATA_DIR` / `EVVP_LOG_DIR` at empty folders. Nothing in the UI is hard-coded: every number is computed from the stored data.

**Docker:** `docker compose up --build` → http://localhost:8000 (JSONL storage, bound to localhost; PostgreSQL is an opt-in, *experimental* profile — see below).
**Optional React app** (`evvp-frontend/`, `npm install && npm run dev`, port 5173) is a legacy secondary UI — see *Status*.

### Configuration (`evvp-backend/.env`, see `.env.example`)

Everything is optional. Recommended: `GITHUB_TOKEN` (otherwise GitHub search is limited to ~10 requests/min) and
`NVD_API_KEY` (higher NVD rate limit). **Leave unused values empty** — never put placeholder text in them.
Set `EVVP_API_TOKEN` to require `Authorization: Bearer <token>` for every write; the dashboard's ⚙ Settings stores it for the session.
The server binds to `127.0.0.1` by default; use a reverse proxy and a token before exposing it.

## Source Manager (dashboard → Sources)

Add, edit, enable/disable, delete, **test** and **collect-now** for any source. Each source has a name, URL, type
(`rss`, `atom`, `api`, `custom`), category (official, vendor, research, news, community), **trust level**
(authoritative, high, medium, low, early_signal), interval (5–1440 min) and enabled flag.

* Sources are never trusted automatically — trust is chosen by the analyst and feeds the risk and zero-day scores.
* Collection runs on each source's own interval; changes apply on the next tick, no restart.
* A failing source records `status=error`, `last_error`, `consecutive_failures`, and backs off exponentially (max 6 h). Other sources are unaffected.
* **Three source types, as in the report:** `rss`/`atom` are collected by a generic feed collector; **`api`/`custom` sources are collected by a generic JSON adapter** — you describe where the fields live with a *field mapping* (`items_path`, `id_field`, `title_field` (required), `url_field`, `date_field`, `text_field`, dotted paths) in the Add/Edit dialog, use *Test source* to preview the parsed entries, and no code is needed. A site with neither feed nor API still needs a hand-written adapter.
* Built-in API collectors: **NVD**, **CISA KEV**, **GitHub**, **Reddit**. They can be disabled, re-trusted and re-scheduled, but not deleted. CISA KEV ingests entries added in the last `EVVP_KEV_LOOKBACK_DAYS` (14) as authoritative, actively-exploited findings (or as evidence on a finding already tracking that CVE).
* **SSRF protection:** URLs must be http(s); private, loopback and link-local targets (including via DNS and redirects) are refused. For local testing only: `EVVP_ALLOW_PRIVATE_SOURCES=1`.

## How scoring works (all of it is shown in the UI)

**Risk (0–100)** = sum of named components, each displayed with its evidence:
signal strength (≤20) + CVSS (≤30) + EPSS (≤25) + CISA KEV (15) *or* reported active exploitation (15) *or* PoC (8)
+ cross-source confirmation (2 sources +3, ≥3 sources +5) + zero-day indicators (+5) + source trust (≤8).
Severity: ≥80 Critical, ≥60 High, ≥40 Medium, else Low (CVSS decides when NVD data exists).

**Potential zero-day candidate** (never "confirmed zero-day"): requires *no CVE* and confidence ≥ 45, built from
no-CVE (+20), zero-day wording (+20), exploitation evidence (+20), PoC evidence (+15), independent sources (+8/+15),
high-trust source (+10), minus 10 if NVD already has a record. Evidence is listed on each candidate.

**Correlation:** reports are merged into one finding when they share a CVE or the same distinctive product/codename
words (generic terms such as "RCE" never merge unrelated stories). Duplicates are kept as evidence (publisher, time, trust).
**Lead time:** earliest *public* signal timestamp vs. CVE publication (falls back to EVVP's own first-collection time,
labelled as such). Missing timestamps are never invented.
**ATT&CK:** mapped only from explicit terms (e.g. remote code execution → T1190) with the matched phrase shown.

## REST API (`/api`)

Reads are open; writes need the bearer token when `EVVP_API_TOKEN` is set. Errors are `{"error": "..."}` with correct status codes.

| Endpoint | Purpose |
|---|---|
| `GET /health`, `/stats` | status; every dashboard number (computed live) |
| `GET /vulns` | findings: `q severity min_risk source platform status cve type zero_day poc active has_cve days sort order page per_page` |
| `GET /vulns/<id>` | detail: risk breakdown, evidence, timeline, lead time, analyst history |
| `POST /vulns/<id>/review` · `/notes` | analyst decision (`potential, under_investigation, confirmed, false_positive, resolved`) + notes |
| `GET /zerodays` · `/cves` · `/cves/<CVE>` | zero-day candidates; CVE intelligence |
| `GET /trending` · `/threat-landscape` | velocity-ranked; aggregate view |
| `GET /sources` · `POST /sources` · `PATCH/DELETE /sources/<id>` | Source Manager CRUD |
| `POST /sources/test` · `/sources/<id>/test` · `/sources/<id>/collect` | dry-run a URL; test a saved source; collect now (202) |
| `GET /audit` · `/audit/stats` | audit trail (`n event q`) |
| `GET /feed/<platform>`, `/search`, `/item/<id>`, `/evidence/<id>`, `/verified` | evidence-level endpoints (older clients) |

## Tests

```bash
cd evvp-backend
python -m unittest discover -s tests -t .   # 94 tests, no network or pytest needed
python tests/run_functions.py               # 4 pytest-style tests without pytest   (or just: pytest)
```

Tests use isolated temp directories and never touch your collected data. They cover: signal detection (every signal in the spec plus
look-alike words such as *force*/*source*), CVE extraction, dedupe boundaries (same story merges, different products with shared generic
words do not), correlation, lead time, risk breakdown, zero-day logic, ATT&CK, NVD/EPSS/KEV handling (incl. outages), source SSRF guard,
analyst workflow, audit, API validation/auth/CORS, and every PostgreSQL code path against a *fake* driver.

## End-to-end demonstration (reproducible, offline) — `scripts/demo.py`

```bash
cd evvp-backend
python scripts/demo.py                 # ~2 min: runs the REAL app against a local simulator of NVD/EPSS/KEV/GitHub/Reddit/RSS
python scripts/demo.py --browser       # also drives the dashboard in headless Chromium (pip install playwright && playwright install chromium)
python scripts/demo.py --keep          # leave app + simulator running so you can click through the dashboard yourself
```

The script walks the scenario below through the real collectors, pipeline, API and (with `--browser`) the real UI, printing PASS/FAIL per check
(175 checks incl. browser). The simulator (`tests/sim/services.py`) is test-only and serves one vulnerability ("Initech Gateway") as it
would unfold in reality, plus an unrelated CVE, a *different* "Gateway" product that must **not** merge, a no-CVE zero-day, noise and hostile HTML:

```
-9h  researcher blog: "unauthenticated RCE zero-day exploited" (no CVE)     -> potential zero-day candidate
-8h  GitHub: PoC repository                                                  -> PoC evidence
-7h  Reddit thread                                                           -> early community signal
-5h  vendor advisory assigns CVE-2026-55501                                  -> merged into the SAME finding, no longer a zero-day candidate
-3h  news coverage
-2h  NVD publishes (CVSS 9.8) · EPSS 74% · CISA KEV listed                   -> risk 95, lead time 7h 0m
then: analyst under_investigation -> confirmed + notes  ·  audit trail  ·  restart (everything persists)
      bad feeds (malformed / HTML / 500 / 429 / timeout / empty)  ·  NVD down -> finding kept, status "unavailable" -> NVD back -> auto re-enrichment
      SSRF probes (localhost, 169.254.169.254, 10.x, ::1, file:, ftp:)  ·  hostile HTML in a feed title  ·  path traversal
```

Manual walk-through in the dashboard (run with `--keep`, open the printed URL, ⚙ Settings → API token `demo-token`):
**Sources → Add source** (type, trust, interval) → *Test source* → *Save* → within one tick the finding appears under **Findings** (no restart);
open it for the timeline / risk breakdown / lead time; record a decision in the **Analyst verification** panel; see every action under **Audit**.
Screenshots from this demo run (simulated data) are in `docs/screenshots/`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Dashboard empty / "API unreachable" | start with `python main.py` (not `--ingest-only`); check http://127.0.0.1:8000/api/health |
| Every source shows `error` | no internet / proxy blocks the feeds; the `last_error` column says why. Collection retries with back-off |
| GitHub collector slow or 403 | set `GITHUB_TOKEN`; unauthenticated search is ~10 requests/min |
| NVD `unavailable` on findings | NVD is rate-limiting/down; findings are kept and re-checked every 30 min. Set `NVD_API_KEY` for a higher limit |
| Source rejected: "private or reserved address" | intentional SSRF protection. For a local test feed only: `EVVP_ALLOW_PRIVATE_SOURCES=1` |
| 401 when saving in the dashboard | `EVVP_API_TOKEN` is set: enter it in ⚙ Settings |
| `.env` values ignored/odd | put comments on their own line; leave unused keys empty |
| Port in use | `EVVP_PORT=8001 python main.py` |

## Layout

```
evvp-backend/  api/ (REST + static host)  ingestion/ (blog, nvd, github, reddit, feed parser)  pipeline/ (signal, enrich, novelty, risk, entities)
               source_manager/  storage/  scheduler/  utils/  web/ (dashboard, no build step)
               tests/ (unit + sim/ simulator)  scripts/ (demo.py, browser_check.py)  raw_data/ data/ logs/
evvp-frontend/ optional React UI        docs/ (GAP_ANALYSIS, screenshots, notes)        legacy_v1/ original prototype (unused)
```

## PostgreSQL (opt-in, strict)

JSONL files are the default store. To use PostgreSQL: `pip install -r requirements-optional.txt`, create a database, set
`DB_URL=postgresql://user:pass@host:5432/dbname` in `.env`, start EVVP (tables are created automatically).
**There is no silent fallback:** if `DB_URL` is set and PostgreSQL (or the driver) is unavailable, EVVP refuses to start with a clear message
(exit code 2); if it fails while running, `/api/health` returns HTTP 503 `{"status":"degraded","storage_error":...}`, data endpoints return 503,
and collectors mark their sources `error: storage error …` instead of reporting a healthy collection. Source registry, analyst decisions and
the audit log stay in files (`data/`, `logs/`) in both modes.

## Live verification on YOUR machine — `scripts/live_check.py`

The automated suite and the demo run against a local simulator. Run this once on a machine with internet access to verify the *real* services
and the full pipeline with real data (it uses temporary directories and never touches your data):

```bash
cd evvp-backend
export GITHUB_TOKEN=...          # optional but recommended; NVD_API_KEY also optional
python scripts/live_check.py     # ~3-6 min; real NVD, EPSS, CISA KEV, GitHub, Reddit, 3 RSS/Atom feeds, then the running app with
                                 # a real RSS source + the real CISA-KEV JSON API added through the Source Manager API,
                                 # collection, enrichment, analyst decision, audit, disable (collection stops) / re-enable (resumes)
python scripts/live_check.py --only nvd epss kev      # any subset: nvd epss kev github reddit rss app
```

Each stage prints PASS / FAIL / BLOCKED (network stopped the request). Exit code 0 = all PASS, 1 = a FAIL, 3 = nothing failed but something was blocked.
Hosts needed: `services.nvd.nist.gov`, `api.first.org`, `www.cisa.gov`, `api.github.com`, `www.reddit.com` (may reject datacenter IPs), and the feed
sites (`www.bleepingcomputer.com`, `krebsonsecurity.com`, `googleprojectzero.blogspot.com`). `python scripts/live_check.py --sim` self-tests the script against the simulator.

## Verification status (honest)

| Area | Status | How it was verified |
|---|---|---|
| Backend, API (all endpoints, validation, auth, CORS, errors) | **PASS** | 94 unit tests + 175-check end-to-end demo against the running app |
| Dashboard (all pages, filters, detail, analyst form, Source Manager lifecycle incl. API-type sources, XSS, mobile layout, no console errors) | **PASS** | real headless Chromium (`demo.py --browser`), repeated runs; screenshots reviewed |
| Collectors → pipeline → finding (RSS, Atom, JSON API, GitHub, Reddit, NVD, CISA KEV) | **PASS against a simulator** | real HTTP + parsing code vs `tests/sim` with realistic payloads and failure injection; real-response shapes (NVD primary/v4 scores, EPSS, KEV, feedparser branch) covered by tests |
| **Live NVD / EPSS / CISA KEV / GitHub / Reddit / real RSS sites** | **NOT VERIFIED** | the build sandbox's egress policy blocks every external host (`x-deny-reason: host_not_allowed`). `scripts/live_check.py` (self-tested here) verifies all of it on a networked machine |
| PostgreSQL | **NOT VERIFIED against a real server** | no PostgreSQL binary/Docker/package index in the sandbox. Verified instead: all code paths vs a fake driver; **strict mode (no silent fallback)**: server down, SQL error, driver missing, collector, API 503 and fail-fast startup are all tested (the startup test uses the real missing-driver condition) |
| Docker / docker compose | **NOT VERIFIED** | no Docker in the sandbox. Verified instead: the image's runtime model — code read-only, unprivileged UID 10001, only `raw_data/data/logs` writable, `EVVP_HOST=0.0.0.0`, the Dockerfile's exact HEALTHCHECK command exits 0, dashboard 200, no permission errors |
| `pip install` from a clean machine | **NOT VERIFIED** | no package index reachable. Requirements split into core + optional with upper bounds; `start.sh` retries core-only, then falls back to system packages; imports audited (only flask/requests/python-dotenv are unconditional) |
| React app (`evvp-frontend/`) | **NOT REQUIRED / not verified** | superseded prototype; the bundled dashboard implements every report page and is the supported UI (see `evvp-frontend/README.md`) |

Design limits: correlation is recomputed in memory (cached) — fine for tens of thousands of items; the SSRF guard resolves DNS before
fetching (a hostile DNS server could in theory rebind between check and fetch — mitigate with an egress firewall); Flask's built-in server is
used (put a production WSGI server/reverse proxy in front for shared deployments); GitHub/Reddit reports about an already-tracked
vulnerability are stored as evidence on that finding (the per-platform feeds list them); NVD requests are spaced to the public limit (6.5 s
per request without an API key, 0.7 s with one), so enrichment of many new CVEs is slow without `NVD_API_KEY`.
