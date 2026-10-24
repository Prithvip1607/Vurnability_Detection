# Gap analysis & changes (EVVP completion pass)

## Starting state
The ZIP was a **mid-merge**: `entities.py`, `analyst.py`, `feedparse.py`, `timeutil.py`, `reenrich.py`, the `web/` dashboard and the
tests targeted a newer design, while `risk.py`, the Source Manager, `db.py`, `server.py`, collectors and the NVD enricher were still the
old versions. `entities.py` imported 7 names that did not exist, so the backend could not import and all 8 test modules errored.
The contract defined by the tests + `entities.py` + `web/` was kept; the missing layers were built to match it.

| Feature | Found | Problem | Done |
|---|---|---|---|
| Startup / imports | broken | missing `risk.py` API, audit constants | rewritten; app starts; 58 tests pass |
| Source Manager | RSS-only list, collectors ignored it | no trust/category/interval/test/collect-now/health | full CRUD, trust, intervals, health, back-off, test, collect-now, audit, SSRF guard |
| Collectors | hard-coded feeds; fabricated GitHub timestamps | one failure path, no per-source status | driven by Source Manager; isolated failures; no invented times |
| NVD enrichment | **dropped the CVE id** when NVD was down | silent data loss | id kept; `nvd_status` ok/partial/not_found/unavailable; periodic re-enrichment |
| NVD collector | first page only, no linking | early signals never joined their CVE record | paging; tracked CVEs force-linked → lead time measurable |
| EPSS / CISA KEV | EPSS per-CVE; no KEV | — | batched EPSS (fail-open); new CISA KEV enrichment |
| Signal matching | substring (`rce` ⊂ *source*, *force*) | false positives | word-boundary matching everywhere |
| Dedupe | keyword fingerprint merged unrelated stories; duplicates lost name/time/trust | wrong merges, lost evidence | distinctive-token rule; duplicates kept as evidence and upgrade the finding |
| Risk / zero-day | opaque reasons, no trust input | not transparent | named components (`risk_breakdown`), trust-weighted, KEV-aware |
| PoC detection | any text with "vulnerability"/"bypass" = PoC | inflated PoC flags | exploit/PoC terms only |
| Storage | PG: invalid `INTERVAL '%s days'`, enrichment never saved; JSON: RFC-2822 dates dropped, verified records never written | data loss / crashes | fixed; `update_raw`; `days=0` = all |
| API | old shapes; no vulns/cves/review/notes/test | UIs could not work | complete REST layer, validation, JSON errors, token auth, strict CORS, CSP/headers, 1 MB body cap |
| Dashboard | complete `web/` UI existed but was not served | — | served at `/` (no build step, strict CSP) |
| Audit | per-process counters, missing event types | API-only mode showed zeros | counters from the persisted log; analyst/source events |
| Config | `.env.example` placeholders sent as real credentials; dotenv `# comment` trap | auth failures | blank values, comments on own lines, defensive parsing; default bind 127.0.0.1 |
| Packaging | Docker/start script stale | — | Dockerfile (non-root, healthcheck), compose (Postgres, volumes), `start.sh`, README |
| Source types (report §7) | only RSS/Atom collectable; `api`/`custom` saved but never collected | one of three source types missing | generic JSON adapter with analyst-defined field mapping (validated, tested, UI form), collected by the scheduler |
| CISA as a source (report §6/§7) | KEV used only as a lookup | CISA not a collectable authoritative source | CISA KEV collector (lookback window, force-linked, no invented timestamps) |
| Final verification pass | — | — | simulator + 175-check E2E incl. real Chromium; bugs fixed: over-dedupe on generic words, SSRF on IP literals, data-dir isolation, analyst-decision overwrite, `0-day` signal, CVE-as-product, evidence charts/feeds, mobile overflow, GitHub retry storm |
| PostgreSQL failure handling | silent fallback to JSON on any PG error; `DB_URL` + missing driver silently used JSON | hidden storage failure ("tests still pass") | strict mode: `StorageError`, fail-fast startup, `/api/health` 503, collectors report storage errors, tests |
| NVD real-world rules | requests paced at ~0.6 s (public limit is 5 per 30 s); first CVSS entry used; v4.0-only CVEs got no score | 403/429 storms; wrong/missing scores on real data | shared throttle (6.5 s / 0.7 s with key), NVD "Primary" score preferred, v3.1 → v3.0 → v4.0 fallback, User-Agent on all calls |
| feedparser branch | lenient parsing accepted broken XML as a valid empty feed | behaviour differed from the tested stdlib parser | bozo + no entries => invalid; branch tested through a faithful stub |
| NVD "not found" | not shown to the analyst | CVE without an NVD record looked normal | exposed as `nvd_status=not_found` ("NO NVD RECORD YET" badge) |
| Live verification | impossible in the sandbox (egress policy) | — | `scripts/live_check.py` (self-tested) for one-command live verification |

