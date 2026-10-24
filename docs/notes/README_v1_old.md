# Early Vulnerability Verification Platform (EVVP)

A production-grade real-time intelligence ingestion, deduplication, and filtering platform that continuously collects, scores, and surfaces emerging cybersecurity vulnerabilities **before official CVE/NVD confirmation**.

---

## What This System Does

- Collects raw intelligence from Reddit, GitHub, NVD, and 18 RSS/blog feeds
- Runs every collected item through a multi-stage threat relevance scoring engine
- Deduplicates cross-source posts — same vulnerability from multiple sources is stored **once**, with all source URLs tracked
- Filters out educational content, career discussions, tool noise, and CI spam
- Stores only high-signal vulnerability candidates with full metadata
- Serves a REST API consumed by a React frontend dashboard
- Frontend shows compact post list — click any post to see full description + all sources

## What This System Does NOT Do

- Classify CVE severity
- Verify vulnerability credibility
- Run ML predictions
- Assign CVSS scores

---

## Project Structure

```
nagal3/
|
|-- evvp-backend/                      # Python Flask backend
|   |-- main.py                        # CLI entry point
|   |-- requirements.txt               # Python dependencies
|   |-- .env.example                   # Environment variable template
|   |-- .env                           # Your actual credentials (git-ignored)
|   |
|   |-- api/
|   |   |-- server.py                  # Flask REST API (port 8000)
|   |
|   |-- ingestion/
|   |   |-- reddit.py                  # Reddit public JSON + RSS fallback
|   |   |-- github.py                  # GitHub API: repos, issues, commits
|   |   |-- blog.py                    # RSS/Atom feed ingestion (18 sources)
|   |   |-- nvd.py                     # NVD feed ingestion
|   |
|   |-- pipeline/
|   |   |-- processor.py               # Main pipeline orchestrator
|   |   |-- signal_filter.py           # Multi-stage threat scoring engine
|   |   |-- novelty.py                 # Cross-source deduplication engine
|   |   |-- nvd_enricher.py            # NVD CVSS enrichment
|   |   |-- verifier.py                # Phase 3 verification engine
|   |   |-- tracker.py                 # CVE trend tracker
|   |   |-- notifier.py                # Webhook / email notifications
|   |
|   |-- storage/
|   |   |-- db.py                      # PostgreSQL + JSONL dual backend
|   |
|   |-- scheduler/
|   |   |-- runner.py                  # Parallel thread runner
|   |
|   |-- config/
|   |   |-- settings.py                # All configuration, keywords, feed URLs
|   |
|   |-- utils/
|   |   |-- logger.py                  # Rotating file + console logging
|   |   |-- retry.py                   # Exponential back-off decorator
|   |   |-- rate_limiter.py            # Token bucket rate limiter
|   |   |-- audit.py                   # System audit trail
|   |
|   |-- raw_data/
|   |   |-- reddit/YYYY-MM-DD.jsonl
|   |   |-- github/YYYY-MM-DD.jsonl
|   |   |-- blog/YYYY-MM-DD.jsonl
|   |   |-- nvd/YYYY-MM-DD.jsonl
|   |
|   |-- logs/
|       |-- main.log
|       |-- api.log
|       |-- ingestion.reddit.log
|       |-- ingestion.github.log
|       |-- ingestion.blog.log
|       |-- ingestion.nvd.log
|       |-- pipeline.log
|       |-- storage.log
|       |-- audit.log
|
|-- evvp-frontend/                     # React + Vite frontend
|   |-- src/
|   |   |-- pages/
|   |   |   |-- Dashboard.tsx          # Stats + charts overview
|   |   |   |-- ZeroDays.tsx           # Pre-CVE candidates
|   |   |   |-- CVEs.tsx               # CVE discussions
|   |   |   |-- Feed.tsx               # Per-platform feed
|   |   |   |-- Trending.tsx           # Trending CVEs
|   |   |   |-- Verified.tsx           # Verification results
|   |   |   |-- Search.tsx             # Full-text search
|   |   |   |-- AuditLog.tsx           # System audit log
|   |   |-- components.tsx             # VulnCard (post row + detail drawer)
|   |   |-- api.ts                     # Axios API client
|   |   |-- App.tsx                    # Routes
|   |   |-- Layout.tsx                 # Sidebar navigation
|   |   |-- index.css                  # Dark theme styles
|   |-- vite.config.ts                 # Vite config + proxy to backend
|   |-- package.json
```

---

## Setup

### 1. Install backend dependencies

```bash
cd evvp-backend
pip install -r requirements.txt
pip install flask-cors
```

### 2. Configure credentials

```bash
cp .env.example .env
```

Edit `.env`:

```env
# GitHub token (required for full rate limits — 5000 req/hour)
GITHUB_TOKEN=your_github_token

# Reddit API (optional — falls back to public JSON without it)
REDDIT_CLIENT_ID=your_reddit_client_id
REDDIT_CLIENT_SECRET=your_reddit_client_secret
REDDIT_USER_AGENT=EVVP/1.0

# NVD API key (optional — removes rate limits)
NVD_API_KEY=your_nvd_api_key

# PostgreSQL (optional — leave empty to use JSONL file storage)
# DB_URL=postgresql://user:password@localhost:5432/evvp
```

### 3. Install frontend dependencies

```bash
cd evvp-frontend
npm install
```

---

## Running

### Start the backend API server

```bash
cd evvp-backend
python main.py --api-only
# API available at http://localhost:8000
```

### Start all ingestion workers + API

```bash
cd evvp-backend
python main.py
```

### Single collection pass (testing / cron)

```bash
python main.py --once
python main.py --once --collector reddit
python main.py --once --collector github
python main.py --once --collector blog
python main.py --once --collector nvd
```

### Start the frontend

```bash
cd evvp-frontend
npm run dev
# Open http://localhost:5173
```

---

## Intelligence Pipeline

Every collected item passes through this pipeline:

```
Raw Item (title + text + metadata)
        |
        v
[1] Signal Scoring (signal_filter.py)
    - 70+ weighted exploit/vuln terms
    - CVE reference bonus (+4 per CVE, capped at +12)
    - 50+ noise/educational penalties
    - Threshold gate — drop low-signal items
        |
        v
[2] NVD Enrichment (nvd_enricher.py)
    - Fetch CVSS v3/v2 scores for any CVE IDs found
        |
        v
[3] Novelty / Deduplication Check (novelty.py)
    - Exact ID match
    - URL match
    - CVE ID overlap
    - Title similarity >= 72%
    - Keyword fingerprint (3+ shared exploit terms)
        |
        +-- DUPLICATE → append new source URL to existing post, stop
        |
        v
[4] Storage (storage/db.py)
    - Save new item with sources: [{url, platform}]
        |
        v
[5] Verification (verifier.py)
    - PoC detection, credibility scoring
        |
        v
[6] CVE Trend Tracking (tracker.py)
        |
        v
[7] Notifications (notifier.py)
    - Webhook / email on novel high-severity items
```

---

## Cross-Source Deduplication

When the same vulnerability is reported by multiple sources (e.g. Reddit, BleepingComputer, GitHub), the system stores **one post only** and appends each additional source URL to the `sources` list.

### How duplicates are detected

| Method | Description |
|--------|-------------|
| Exact ID | Same item re-collected |
| URL match | Same article URL |
| CVE overlap | Both posts reference the same CVE ID |
| Title similarity | Jaccard token overlap >= 72% |
| Keyword fingerprint | 3+ shared high-signal exploit terms (zero-day, rce, poc, etc.) |

### Stored item with multiple sources

```json
{
  "id": "blog_abc123",
  "title": "Apache RCE Zero-Day PoC Released",
  "signal_score": 28,
  "sources": [
    { "url": "https://bleepingcomputer.com/...", "platform": "blog" },
    { "url": "https://reddit.com/r/netsec/...", "platform": "reddit" },
    { "url": "https://github.com/...",           "platform": "github" }
  ]
}
```

---

## Output Schema

```json
{
  "id": "blog_abc123",
  "platform": "reddit | github | blog | nvd",
  "source": "bleepingcomputer.com",
  "title": "PAN-OS Zero-Day Unauthenticated RCE",
  "text": "Plain text description...",
  "author": "username",
  "timestamp": "2026-05-15T09:27:50+00:00",
  "url": "https://...",
  "metadata": {},
  "signal_score": 31,
  "category": "high_confidence_vulnerability_signal",
  "matched_signals": ["zero-day", "remote code execution", "unauthenticated", "rce"],
  "negative_signals": [],
  "collected_at": "2026-05-15T09:27:50+00:00",
  "sources": [
    { "url": "https://...", "platform": "blog" },
    { "url": "https://...", "platform": "reddit" }
  ],
  "cve_ids": ["CVE-2026-1234"],
  "nvd_data": [{ "cvss_v3": { "score": 9.8, "severity": "CRITICAL" } }]
}
```

---

## Frontend UI

The frontend is a React + Vite app served at `http://localhost:5173`. It proxies all `/api` requests to the backend at `http://localhost:8000`.

### Pages

| Page | Route | Description |
|------|-------|-------------|
| Dashboard | `/` | Stats cards, timeline chart, category breakdown |
| All Findings | `/vulns` | All collected intelligence |
| Zero-Days | `/zerodays` | High-signal items with NO CVE ID |
| CVEs | `/cves` | Items with CVE IDs actively discussed |
| Trending | `/trending` | CVEs trending by mention count |
| Verified | `/verified` | Phase 3 verification results |
| Reddit | `/feed/reddit` | Reddit-only feed |
| GitHub | `/feed/github` | GitHub-only feed |
| Blogs / RSS | `/feed/blog` | Blog/RSS-only feed |
| NVD Feed | `/feed/nvd` | NVD-only feed |
| Search | `/search` | Full-text search |
| Audit Log | `/audit` | System activity trail |

### Post interaction

- Each page shows a **compact post list** — score badge, title, platform, severity, time ago
- Click any post → **detail drawer** slides in from the right showing:
  - Full description (plain text, HTML stripped)
  - CVSS score if available
  - CVE ID tags
  - Matched signal tags
  - **Sources section** — each source is a clickable link that opens the original post in a new tab

---

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/health` | Backend health check |
| `GET /api/stats` | Totals, platform counts, category counts, timeline |
| `GET /api/feed/<platform>` | Feed for reddit / github / blog / nvd / all |
| `GET /api/zerodays` | High-signal items with no CVE ID |
| `GET /api/cves` | Items with CVE IDs |
| `GET /api/trending` | Trending CVEs by mention count |
| `GET /api/search?q=<query>` | Full-text search |
| `GET /api/verified` | Phase 3 verification results |
| `GET /api/audit` | Recent audit log entries |
| `GET /api/audit/stats` | Aggregate audit counters |

---

## Storage

### JSONL files (default)

No configuration needed. Files written to:

```
raw_data/
  reddit/YYYY-MM-DD.jsonl
  github/YYYY-MM-DD.jsonl
  blog/YYYY-MM-DD.jsonl
  nvd/YYYY-MM-DD.jsonl
  verifications.jsonl
  cve_mentions.jsonl
```

### PostgreSQL (optional)

Set `DB_URL` in `.env`. Schema is auto-created on first run including the `sources` JSONB column.

---

## Signal Scoring Reference

### High-value positive signals (sample)

| Term | Score |
|------|-------|
| actively exploited | 10 |
| exploited in the wild | 10 |
| 0day / zero-day | 9 |
| unauthenticated rce | 9 |
| sandbox escape | 9 |
| kernel exploit | 9 |
| remote code execution | 8 |
| auth bypass | 8 |
| memory corruption / use-after-free | 8 |
| rce | 7 |
| privilege escalation | 7 |
| poc / proof of concept | 6 |
| CVE reference | +4 each (max 12) |

### Noise penalties (sample)

| Term | Penalty (body) | Penalty (title) |
|------|---------------|-----------------|
| how to learn | 10 | 20 |
| tutorial | 8 | 16 |
| dependabot | 9 | 18 |
| career | 7 | 14 |
| certification | 7 | 14 |

---

## Categories

| Category | Stored? | Description |
|----------|---------|-------------|
| `high_confidence_vulnerability_signal` | Yes | RCE, auth bypass, PoC, active exploitation, zero-day |
| `exploit_development_discussion` | Yes | Shellcode, ROP chains, heap grooming, bypass techniques |
| `educational_tutorial_content` | No | Tutorials, courses, beginner guides |
| `general_cybersecurity_discussion` | No | Career, tools, generic security chat |

---

## Data Sources

### Reddit (8 subreddits)
r/netsec, r/cybersecurity, r/hacking, r/exploitdev, r/bugbounty, r/ReverseEngineering, r/blueteamsec, r/AskNetsec

### GitHub
Repos, issues, and commits searched across 25 exploit/vulnerability keywords. Authenticated via `GITHUB_TOKEN` (5000 req/hour).

### Security Blogs / RSS (18 sources)
The Hacker News, BleepingComputer, Dark Reading, SecurityWeek, Krebs on Security, Google Project Zero, ProjectDiscovery, PortSwigger Research, Unit 42, Microsoft Security, Help Net Security, CyberScoop, Trend Micro Research, and more.

### NVD
National Vulnerability Database feed for CVE enrichment and CVSS scores.

---

## Rate Limiting

| Source | Limit | Notes |
|--------|-------|-------|
| Reddit | ~1 req/sec | Public JSON, no auth needed |
| GitHub (unauthenticated) | 10 req/hour | Very limited |
| GitHub (authenticated) | 5000 req/hour | Set `GITHUB_TOKEN` |
| RSS feeds | No limit | 20s timeout per feed |
| NVD (unauthenticated) | 5 req/30s | Set `NVD_API_KEY` for higher limits |

---

## Polling Intervals

| Collector | Default | Override via `.env` |
|-----------|---------|---------------------|
| Reddit | 300s (5 min) | `REDDIT_POLL_INTERVAL` |
| GitHub | 600s (10 min) | `GITHUB_POLL_INTERVAL` |
| Blog/RSS | 900s (15 min) | `BLOG_POLL_INTERVAL` |
| NVD | 3600s (1 hour) | `NVD_POLL_INTERVAL` |

---

## Dependencies

### Backend
```
praw>=7.7           # Reddit API
feedparser>=6.0     # RSS/Atom parsing
requests>=2.31      # HTTP client
python-dotenv>=1.0  # .env loading
flask>=3.0          # REST API server
flask-cors>=4.0     # CORS for frontend
psycopg2-binary>=2.9 # PostgreSQL (optional)
```

### Frontend
```
react ^18          # UI framework
react-router-dom   # Routing
axios              # HTTP client
recharts           # Charts
vite + typescript  # Build tooling
```

---

## Architecture Summary

```
Internet Sources
    |
    +-- Reddit (public JSON + RSS)
    +-- GitHub API (repos, issues, commits)
    +-- RSS/Blog feeds (18 sources)
    +-- NVD feed
    |
    v
Ingestion (ingestion/)
    |
    v
Pipeline (pipeline/)
    |-- Signal scoring      → drop low-signal items
    |-- NVD enrichment      → add CVSS scores
    |-- Novelty check       → deduplicate cross-source posts
    |-- Storage             → save new / append source to existing
    |-- Verification        → credibility scoring
    |-- CVE trend tracking
    |-- Notifications
    |
    v
Storage (storage/db.py)
    |-- JSONL files (default)
    |-- PostgreSQL (optional)
    |
    v
REST API (api/server.py — port 8000)
    |-- HTML stripped from all text fields before response
    |
    v
React Frontend (evvp-frontend — port 5173)
    |-- Compact post list
    |-- Click post → detail drawer
    |-- Sources section → click any source → opens original post
```

## EVVP Intelligence v2

This version adds an explainable intelligence layer on top of the existing collectors and pipeline:

- **EPSS enrichment** from FIRST for known CVEs
- **Risk score (0–100)** combining signal strength, CVSS, EPSS, exploitation and corroboration
- **Zero-day confidence (0–100)** instead of treating every no-CVE item as a zero-day
- **Cross-source corroboration** across Reddit, GitHub, blogs and NVD observations
- **MITRE ATT&CK technique mapping** using explainable keyword evidence
- **Evidence API** for source/evidence/risk inspection
- **Threat Landscape API** for severity, platform, category, risk and attack-technique analytics
- **Analyst search API** for quick evidence-backed retrieval from collected intelligence
- **Automated tests** under `evvp-backend/tests`
- **Docker / Compose** for repeatable backend + PostgreSQL startup

### New API endpoints

`GET /api/threat-landscape?days=30`  
`GET /api/evidence/<item_id>`  
`GET /api/analyst?q=apache`  

### Risk interpretation

Risk is a prioritization signal, not proof of exploitation. Zero-day candidates are labelled as candidates until independently verified.

### Run tests

```bash
cd evvp-backend
pytest
```

### Docker

```bash
docker compose up --build
```


## Dynamic Source Intelligence Manager

EVVP now includes a dynamic RSS/Atom source manager. Sources can be added from the dashboard/API without editing the Python source-code feed list.

### API

- `GET /api/sources` — list configured sources
- `POST /api/sources` — add a source: `{"name":"Example Security","url":"https://example.com/feed.xml","type":"rss"}`
- `POST /api/sources/test` — validate a feed before saving: `{"url":"https://example.com/feed.xml"}`
- `PATCH /api/sources/<id>` — enable/disable or edit a source
- `DELETE /api/sources/<id>` — remove a source

Sources are stored in `data/sources.json` by default. Set `EVVP_SOURCES_FILE` to use another location.

### Register the blueprint

In the Flask app that creates `app = Flask(__name__)`, add:

```python
from source_manager.routes import sources_bp
app.register_blueprint(sources_bp)
```

### Use dynamic sources in the blog collector

Replace the hard-coded RSS URL loop with:

```python
from source_manager.manager import active_sources

for source in active_sources():
    feed_url = source["url"]
    # existing feed parsing + EVVP processing here
```

This keeps the existing vulnerability-processing pipeline intact while making the source list configurable at runtime.
