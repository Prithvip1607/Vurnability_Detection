#!/usr/bin/env python3
"""EVVP end-to-end demonstration + verification (reproducible, offline).

Starts the *real* EVVP application (collectors + API + dashboard) in a temporary directory, points it at a local
simulator of NVD / EPSS / CISA KEV / GitHub / Reddit / RSS, and then walks the whole pipeline through the REST API:

  add sources (no restart) -> scheduler collects -> normalise/dedupe -> signals -> CVE -> NVD/EPSS/KEV -> correlation
  -> risk -> zero-day -> ATT&CK -> timeline & lead time -> analyst decision -> audit -> restart (persistence)
  -> failure handling (bad feeds, NVD down, then recovery) -> SSRF protection

Usage:
    python scripts/demo.py                # run everything, print PASS/FAIL per check, exit 1 on any failure
    python scripts/demo.py --keep         # afterwards keep app + simulator running so you can explore the dashboard
    python scripts/demo.py --browser      # also drive the dashboard in a real headless browser (needs playwright)

NOTE: the simulator is NOT the live internet. Live NVD/GitHub/Reddit/RSS collection must be checked separately
(`python main.py --once` with network access).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests.sim import services as sim  # noqa: E402
from source_manager.manager import BUILTINS  # noqa: E402

TOKEN = "demo-token"
RESULTS: list[tuple[bool, str, str]] = []


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def check(name: str, ok: bool, detail: str = "") -> bool:
    RESULTS.append((bool(ok), name, detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   [{detail}]" if detail and not ok else (f"   ({detail})" if detail else "")), flush=True)
    return bool(ok)


def section(title: str) -> None:
    print(f"\n=== {title}", flush=True)


class Api:
    def __init__(self, base: str):
        self.base = base

    def __call__(self, method: str, path: str, body=None, token: str | None = TOKEN, raw: bool = False):
        h = {"Content-Type": "application/json"}
        if token:
            h["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(self.base + "/api" + path, method=method, headers=h,
                                     data=json.dumps(body).encode() if body is not None else None)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.load(e)
            except Exception:
                return e.code, None


def wait_for(fn, timeout: float = 45, every: float = 0.7):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            last = fn()
            if last:
                return last
        except Exception:
            pass
        time.sleep(every)
    return last


class App:
    def __init__(self, env: dict, args: list[str], port: int):
        self.port, self.env, self.args = port, env, args
        self.proc: subprocess.Popen | None = None
        self.log = tempfile.NamedTemporaryFile("w+", suffix=".log", delete=False)

    def start(self):
        env = {**os.environ, **self.env, "EVVP_PORT": str(self.port), "PYTHONPATH": ROOT}
        self.proc = subprocess.Popen([sys.executable, "main.py", *self.args], cwd=ROOT, env=env, stdout=self.log, stderr=subprocess.STDOUT)
        api = Api(f"http://127.0.0.1:{self.port}")
        ok = wait_for(lambda: api("GET", "/health", token=None)[0] == 200, 30)
        return api if ok else None

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGINT)
            try:
                self.proc.wait(8)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--browser", action="store_true")
    ap.add_argument("--screenshots", action="store_true", help="with --browser: save demo screenshots to docs/screenshots/")
    ap.add_argument("--workdir")
    opts = ap.parse_args()

    work = opts.workdir or tempfile.mkdtemp(prefix="evvp-demo-")
    os.makedirs(work, exist_ok=True)
    sim_port, app_port = free_port(), free_port()
    S = f"http://127.0.0.1:{sim_port}"
    sim.start(sim_port)
    env = {
        "EVVP_RAW_DATA_DIR": f"{work}/raw", "EVVP_DATA_DIR": f"{work}/data", "EVVP_LOG_DIR": f"{work}/logs",
        "EVVP_API_TOKEN": TOKEN, "EVVP_ALLOW_PRIVATE_SOURCES": "1", "EVVP_TICK_SECONDS": "2", "EVVP_CACHE_TTL": "1",
        "NVD_BASE_URL": f"{S}/nvd", "EPSS_URL": f"{S}/epss", "KEV_URL": f"{S}/kev.json", "GITHUB_API_URL": f"{S}/github",
        "REDDIT_BASE_URL": f"{S}/reddit", "NVD_MIN_INTERVAL_SECONDS": "0", "GITHUB_REQUESTS_PER_HOUR": "100000", "GITHUB_TOKEN": "", "NVD_API_KEY": "", "DB_URL": "",
    }
    os.makedirs(f"{work}/data", exist_ok=True)
    seed = [{**b, "enabled": False, "builtin": True} for b in BUILTINS]       # only the 3 built-ins, all disabled: nothing talks to the internet
    json.dump(seed, open(f"{work}/data/sources.json", "w"))
    print(f"workdir: {work}\nsimulator: {S}\n")

    app = App(env, [], app_port)
    api = app.start()
    if not api:
        print("FAIL: application did not start\n" + open(app.log.name).read()[-2000:])
        return 1
    base = f"http://127.0.0.1:{app_port}"

    # ── 1. startup & security basics ──────────────────────────────────────────
    section("1. Startup, health, access control")
    s, h = api("GET", "/health", token=None)
    check("health endpoint (open read)", s == 200 and h["status"] == "ok" and h["storage"] == "jsonl", str(h))
    check("empty dataset is handled (0 findings)", h["findings"] == 0 and api("GET", "/vulns")[1]["total"] == 0)
    check("write without token -> 401", api("POST", "/sources", {"name": "x", "url": S + "/feeds/news.xml"}, token=None)[0] == 401)
    check("write with wrong token -> 401", api("POST", "/sources", {"name": "x", "url": S + "/feeds/news.xml"}, token="nope")[0] == 401)

    # ── 2. Source Manager: add a source, scheduler discovers it (no restart) ──
    section("2. Source Manager -> scheduler discovers new source (no restart)")
    s, v = api("POST", "/sources/test", {"url": S + "/feeds/researcher.xml", "type": "rss", "actor": "alice"})
    check("test-before-add: valid feed", s == 200 and v["valid"] and v["entry_count"] == 3, str(v)[:120])
    s, src = api("POST", "/sources", {"name": "Researcher Blog", "url": S + "/feeds/researcher.xml", "type": "rss", "category": "research",
                                      "trust": "high", "interval_minutes": 5, "actor": "alice"})
    check("add source (201)", s == 201 and src["trust"] == "high" and src["interval_minutes"] == 5)
    rid = src["id"]

    def src_state(sid):
        return next((x for x in api("GET", "/sources")[1]["sources"] if x["id"] == sid), {})
    st = wait_for(lambda: src_state(rid).get("status") == "healthy" and src_state(rid))
    check("collector discovered + collected the new source on its own", bool(st), "")
    check("source health fields (last_success, item count, saved)", bool(st) and st["last_success"] and st["last_item_count"] == 3 and st["total_collected"] == 2,
          str({k: st.get(k) for k in ("status", "last_item_count", "total_collected")}))
    fr = api("GET", "/vulns?q=initech")[1]
    check("finding appeared in the dashboard API", fr["total"] == 1, f"total={fr['total']}")
    check("noise item (team picnic) filtered out", api("GET", "/vulns?q=picnic")[1]["total"] == 0)
    first = fr["items"][0]
    check("no CVE yet -> potential zero-day candidate (not a certainty)", first["zero_day_candidate"] and not first["cve_ids"] and 45 <= first["zero_day_score"] <= 100,
          f"score={first['zero_day_score']}")
    check("trust of the source flows into the finding", "high" in json.dumps(api("GET", f"/vulns/{first['id']}")[1]["evidence"]))

    # ── 3. more sources, all collector types ──────────────────────────────────
    section("3. GitHub, Reddit, vendor/news/atom feeds, NVD")
    for sid in ("builtin-github", "builtin-reddit"):
        s, _ = api("PATCH", f"/sources/{sid}", {"enabled": True, "actor": "alice"})
        check(f"enable {sid}", s == 200)
    ids = {}
    for name, path, typ, cat, trust in (("Initech Security Advisories", "vendor.xml", "rss", "vendor", "authoritative"),
                                        ("Sim Security News", "news.xml", "rss", "news", "medium"),
                                        ("Sim Atom Feed", "atom.xml", "atom", "research", "high"),
                                        ("XSS Probe Feed", "xss.xml", "rss", "news", "low"),
                                        ("Dup Feed", "dup.xml", "rss", "news", "low")):
        s, r = api("POST", "/sources", {"name": name, "url": f"{S}/feeds/{path}", "type": typ, "category": cat, "trust": trust, "interval_minutes": 5})
        ids[name] = r.get("id")
        check(f"add {name} ({typ}, {trust})", s == 201)
    for sid in ("builtin-github", "builtin-reddit", *ids.values()):
        ok = wait_for(lambda sid=sid: src_state(sid).get("status") == "healthy")
        check(f"{sid} collected", bool(ok), str(src_state(sid).get("last_error")))
    s, r = api("PATCH", "/sources/builtin-cisa-kev", {"enabled": True, "actor": "alice"})
    check("enable CISA KEV source", s == 200)
    s, r = api("POST", "/sources", {"name": "Advisory JSON API", "url": S + "/api/advisories.json", "type": "api", "category": "vendor", "trust": "high", "interval_minutes": 5,
                                    "mapping": {"items_path": "data.advisories", "id_field": "advisory_id", "title_field": "name", "url_field": "link", "date_field": "issued", "text_field": "summary"}})
    check("add generic JSON API source with a field mapping (report: source type 1/3)", s == 201 and r["collectable"] is True and r["mapping"]["title_field"] == "name", str(r)[:150])
    ids["Advisory JSON API"] = r.get("id")
    api("PATCH", "/sources/builtin-nvd", {"enabled": True, "actor": "alice"})
    check("NVD collector ran", bool(wait_for(lambda: src_state("builtin-nvd").get("status") == "healthy")), str(src_state("builtin-nvd").get("last_error")))
    check("CISA KEV collector ran", bool(wait_for(lambda: src_state("builtin-cisa-kev").get("status") == "healthy")), str(src_state("builtin-cisa-kev").get("last_error")))
    soy = api("GET", "/vulns?q=soylent")[1]
    sd = api("GET", f"/vulns/{soy['items'][0]['id']}")[1] if soy["total"] else {}
    check("KEV-only CVE becomes a finding: authoritative, KEV, actively exploited", soy["total"] == 1 and sd.get("kev") is True and sd.get("active_exploitation") is True and "cisa" in sd.get("platforms", []),
          str({k: sd.get(k) for k in ("kev", "active_exploitation", "platforms")}))
    check("KEV entry older than the lookback window is ignored", api("GET", "/vulns?q=oldware")[1]["total"] == 0)
    check("KEV listing date is not used as an invented observation time", all(not e.get("observed_at_precise") for e in sd.get("evidence", [])) and sd.get("first_seen") is not None)
    wait_for(lambda: src_state(ids["Advisory JSON API"]).get("status") == "healthy", 40)
    time.sleep(1.5)
    vd = api("GET", "/vulns?q=vandelay")[1]
    check("JSON API source: finding generated from mapped fields (empty-title row skipped)", vd["total"] == 1 and sorted(vd["items"][0]["cve_ids"]) == ["CVE-2026-81001"] and src_state(ids["Advisory JSON API"]).get("last_item_count") == 1,
          str(src_state(ids["Advisory JSON API"]).get("last_item_count")))
    m_ok = {"items_path": "data.advisories", "title_field": "name", "date_field": "issued"}
    s1, r1 = api("POST", "/sources/test", {"url": S + "/api/advisories.json", "type": "api", "mapping": m_ok})
    s2, r2 = api("POST", "/sources/test", {"url": S + "/api/advisories.json", "type": "api", "mapping": {**m_ok, "items_path": "data.nope"}})
    s3, r3 = api("POST", "/sources/test", {"url": S + "/api/notjson", "type": "api", "mapping": m_ok})
    s4 = api("POST", "/sources", {"name": "x", "url": S + "/api/other", "type": "api"})[0]
    s5 = api("POST", "/sources", {"name": "x", "url": S + "/api/other2", "type": "custom", "mapping": {"title_field": "a b; rm -rf /"}})[0]
    s6 = api("POST", "/sources", {"name": "x", "url": S + "/api/other3", "type": "custom", "mapping": {"title_field": "t", "bogus": "x"}})[0]
    check("JSON source tests: preview OK; wrong path / non-JSON -> 422; missing or malicious mapping -> 400", (s1, s2, s3, s4, s5, s6) == (200, 422, 422, 400, 400, 400) and r1["entry_count"] == 1, str((s1, s2, s3, s4, s5, s6)))
    check("duplicate content in one feed collapses to one finding", api("GET", "/vulns?q=duplicate%20co")[1]["total"] == 1)
    time.sleep(2.5)

    # ── 4. correlation, enrichment, scoring ───────────────────────────────────
    section("4. Correlation, enrichment (NVD/EPSS/KEV), risk, zero-day, ATT&CK, lead time")
    fr = api("GET", "/vulns?q=initech")[1]
    check("Initech reports from 6 places = ONE finding", fr["total"] == 1, f"total={fr['total']}")
    d = api("GET", f"/vulns/{fr['items'][0]['id']}")[1]
    check("cross-source: independent sources counted", d["cross_source_count"] >= 5, f"{d['cross_source_count']}: {d['sources']}")
    check("sources span blog, github, reddit, vendor, nvd", {"blog", "github", "reddit", "nvd"} <= set(d["platforms"]), str(d["platforms"]))
    check("CVE extracted & normalised", d["cve_ids"] == [sim.CVE_INITECH], str(d["cve_ids"]))
    check("NVD: CVSS 9.8 / CRITICAL / references / products", d["cvss"] == 9.8 and d["severity"] == "CRITICAL" and d["references"] and d["affected_products"],
          f"cvss={d['cvss']} sev={d['severity']}")
    check("EPSS score, percentile and data date", d["epss"] == 0.74 and d["epss_percentile"] == 0.98 and bool(d.get("epss_date")), f"{d['epss']} {d['epss_percentile']} {d.get('epss_date')}")
    check("CISA KEV recognised", d["kev"] is True)
    check("active exploitation true (KEV + reports)", d["active_exploitation"] is True)
    factors = {p["factor"] for p in d["risk_breakdown"]}
    check("risk breakdown has real components", {"CVSS", "EPSS", "CISA KEV", "Source trust", "Cross-source confirmation"} <= factors, str(sorted(factors)))
    check("risk breakdown sums to the score", min(100, sum(p["points"] for p in d["risk_breakdown"])) == d["risk_score"] and d["risk_score"] >= 80, f"risk={d['risk_score']}")
    check("has a CVE -> NOT a zero-day candidate", d["zero_day_candidate"] is False)
    check("ATT&CK T1190 mapped with matched phrase", any(t["id"] == "T1190" and t["matched"] for t in d["attack_techniques"]), str(d["attack_techniques"]))
    lt = d["lead_time"]
    check("lead time: early warning measured from stored timestamps", lt["status"] == "early" and 6.5 * 3600 <= lt.get("seconds", 0) <= 7.5 * 3600, str(lt))
    ev = [e["label"] if isinstance(e, dict) else e for e in d["timeline"]["events"]]
    check("timeline has researcher -> PoC -> vendor -> CVE/NVD events", len(ev) >= 5, f"{len(ev)} events")
    times = [e["ts"] for e in d["timeline"]["events"]]
    check("timeline is chronological", times == sorted(times))
    wayne = api("GET", "/vulns?q=wayne")[1]
    check("different product sharing only 'Gateway' is NOT merged", wayne["total"] == 1 and wayne["items"][0]["id"] != d["id"])
    globex = api("GET", "/vulns?cve=CVE-2026-60010")[1]
    gd = api("GET", f"/vulns/{globex['items'][0]['id']}")[1] if globex["total"] else {}
    check("unrelated CVE stays a separate finding with its own CVSS", globex["total"] == 1 and gd.get("cvss") == 7.5 and gd["id"] != d["id"])
    check("'PoC exploit' text alone is NOT active exploitation", gd.get("poc") is True and gd.get("active_exploitation") is False)
    check("SQL injection mapped to T1190", any(t["id"] == "T1190" for t in gd.get("attack_techniques", [])))
    zd = api("GET", "/zerodays")[1]
    zt = {x["title"].split(" ")[0] for x in zd["items"]}
    check("zero-day page: Umbrella (Atom feed) + Duplicate Co + Wayne candidates", {"Umbrella", "Duplicate", "Wayne"} <= zt, str(sorted(zt)))
    check("zero-day page excludes CVE-assigned findings", not ({"Initech", "Globex"} & zt))
    check("zero-day items carry confidence + evidence", all(x["zero_day_evidence"] and x["zero_day_score"] >= 45 for x in zd["items"]))
    c = api("GET", f"/cves/{sim.CVE_INITECH}")[1]
    check("CVE page: description, CVSS, EPSS, KEV, sources, timeline", c["cvss"] == 9.8 and c["epss"] == 0.74 and c["description"] and c["sources"] and c["timeline"])
    tr = api("GET", "/trending?hours=0&top=5")[1]
    check("trending is ranked by velocity score, Initech first", tr and tr[0]["cve_id"] == sim.CVE_INITECH and tr[0]["source_count"] >= 5, str(tr[0]["trend"]) if tr else "")
    tl = api("GET", "/threat-landscape?days=0")[1]
    check("threat landscape from real data", tl["total"] >= 5 and tl["attack_techniques"] and tl["top_sources"] and tl["categories"])
    stt = api("GET", "/stats")[1]
    check("stats: counters match the data", stt["potential_zero_days"] == zd["total"] and stt["total_findings"] == api("GET", "/vulns")[1]["total"] and stt["early_detections"] >= 1 and stt["critical_cves"] >= 1,
          str({k: stt[k] for k in ("total_findings", "potential_zero_days", "early_detections", "critical_cves", "active_exploitation")}))
    check("stats: sources_over_time / findings_over_time populated", bool(stt["sources_over_time"]) and bool(stt["findings_over_time"]))
    plats = {k for r in stt["sources_over_time"] for k in r if k != "date"}
    check("stats: evidence-by-platform counts GitHub/Reddit evidence folded into findings", {"blog", "github", "reddit", "nvd"} <= plats, str(plats))

    for plat in ("blog", "github", "reddit", "nvd", "cisa"):
        s_, fd = api("GET", f"/feed/{plat}?per_page=5", token=None)
        check(f"/api/feed/{plat}: items, all of that platform, scored", s_ == 200 and fd["total"] >= 1 and all(i["platform"] == plat for i in fd["items"]), f"{s_} {fd and fd.get('total')}")
    s_, fd = api("GET", "/feed/all?per_page=3", token=None)
    check("/api/feed/all pagination", s_ == 200 and len(fd["items"]) == 3 and fd["pages"] >= 2)
    check("/api/feed/bogus -> 400, /api/nope -> JSON 404", api("GET", "/feed/bogus", token=None)[0] == 400 and api("GET", "/nope", token=None) == (404, {"error": "not found"}))
    ev = api("GET", f"/evidence/{d['id']}", token=None)[0]
    raw_id = api("GET", "/feed/nvd?per_page=1", token=None)[1]["items"][0]["id"]
    check("/api/evidence, /api/item, /api/search, /api/verified work", api("GET", f"/evidence/{raw_id}", token=None)[0] == 200 and api("GET", f"/item/{raw_id}", token=None)[0] == 200
          and api("GET", "/search?q=initech", token=None)[1]["total"] >= 1 and api("GET", "/verified", token=None)[0] == 200 and api("GET", "/search?q=ab", token=None)[0] == 400)
    xss = api("GET", "/vulns?q=acme%20cam")[1]
    check("hostile HTML in a feed is stored as inert text (finding exists, API returns it verbatim)", xss["total"] == 1 and "<img" in xss["items"][0]["title"])

    # ── 5. analyst workflow, audit ────────────────────────────────────────────
    section("5. Analyst workflow and audit trail")
    eid = d["id"]
    s, e1 = api("POST", f"/vulns/{eid}/review", {"status": "under_investigation", "analyst": "alice", "notes": "Checking vendor advisory."})
    s2, e2 = api("POST", f"/vulns/{eid}/review", {"status": "confirmed", "analyst": "alice", "notes": "Confirmed by vendor advisory IN-2026-001."})
    s3, _ = api("POST", f"/vulns/{eid}/notes", {"analyst": "bob", "notes": "Patch 4.2.1 deployed on staging."})
    check("review -> under_investigation -> confirmed + note (201)", (s, s2, s3) == (201, 201, 201))
    check("invalid status / empty analyst / unknown finding rejected", (api("POST", f"/vulns/{eid}/review", {"status": "maybe", "analyst": "a"})[0],
          api("POST", f"/vulns/{eid}/review", {"status": "confirmed", "analyst": ""})[0], api("POST", "/vulns/nope/review", {"status": "confirmed", "analyst": "a"})[0]) == (400, 400, 404))
    time.sleep(1.2)
    d2 = api("GET", f"/vulns/{eid}")[1]
    check("status persisted with analyst, notes, timestamp", d2["analyst"]["status"] == "confirmed" and (d2["analyst"]["decision"] or {}).get("analyst") == "alice" and d2["analyst"]["decision"].get("ts") and d2["analyst"]["decision"].get("notes"), str(d2["analyst"]))
    check("history has all 3 entries", len(d2["analyst_history"]) == 3, str([(h["kind"], h["analyst"], h["status"]) for h in d2["analyst_history"]]))
    check("filter by analyst status", api("GET", "/vulns?status=confirmed")[1]["total"] == 1)
    api("POST", f"/sources/{rid}/collect", {"actor": "alice"})
    api("PATCH", f"/sources/{ids['Dup Feed']}", {"trust": "medium", "interval_minutes": 15, "actor": "alice"})
    api("PATCH", f"/sources/{ids['Dup Feed']}", {"enabled": False, "actor": "alice"})
    time.sleep(2.5)
    events = {x["event"] for x in api("GET", "/audit?n=1000")[1]}
    need = {"source_added", "source_edited", "source_enabled", "source_disabled", "source_tested", "source_collect_triggered", "source_collected",
            "finding_reviewed", "finding_confirmed", "analyst_note_added", "item_novel", "item_dropped", "item_duplicate", "nvd_enriched"}
    check("audit trail covers source, collection, analyst and pipeline actions", need <= events, f"missing={sorted(need - events)}")
    au = api("GET", "/audit?n=5&event=finding_confirmed")[1]
    check("audit entry names the analyst", au and au[-1].get("actor") == "alice", str(au[-1:])[:150])
    check("audit stats come from persisted log", api("GET", "/audit/stats")[1]["items_collected"] > 5)

    # ── 6. failure handling ───────────────────────────────────────────────────
    section("6. Failure handling: bad feeds, timeouts, NVD down & recovery")
    before = api("GET", "/vulns")[1]["total"]
    for path, label in (("malformed.xml", "malformed XML"), ("notafeed.html", "HTML instead of a feed"), ("500", "HTTP 500"), ("429", "HTTP 429")):
        s, r = api("POST", "/sources/test", {"url": f"{S}/feeds/{path}", "type": "rss"})
        check(f"test-source: {label} -> 422 with a readable reason", s == 422 and r["valid"] is False and r["error"], r.get("error", "")[:80] if r else "")
    s, r = api("POST", "/sources/test", {"url": S + "/feeds/empty.xml", "type": "rss"})
    check("test-source: empty feed is valid with 0 entries", s == 200 and r["entry_count"] == 0)
    t0 = time.time()
    s, r = api("POST", "/sources/test", {"url": S + "/feeds/slow", "type": "rss"})
    check("test-source: timeout -> 422 (no hang)", s == 422 and "timed out" in r["error"] and time.time() - t0 < 30, f"{time.time() - t0:.0f}s")
    bad = {}
    for path in ("malformed.xml", "500", "429", "empty.xml"):
        s, r = api("POST", "/sources", {"name": f"Bad {path}", "url": f"{S}/feeds/{path}", "type": "rss", "trust": "low", "interval_minutes": 5})
        bad[path] = r["id"]
    time.sleep(1)
    wait_for(lambda: all(src_state(i).get("last_fetched") for i in bad.values()), 30)
    check("failing sources are flagged error with last_error + failure count", all(src_state(bad[p]).get("status") == "error" and src_state(bad[p]).get("last_error") and src_state(bad[p]).get("consecutive_failures") == 1 for p in ("malformed.xml", "500", "429")),
          str({p: src_state(bad[p]).get("status") for p in bad}))
    check("empty feed is healthy with 0 items", src_state(bad["empty.xml"]).get("status") == "healthy" and src_state(bad["empty.xml"]).get("last_item_count") == 0)
    check("failures did not disturb existing findings / other sources", api("GET", "/vulns")[1]["total"] == before and src_state(rid).get("status") == "healthy")
    check("health reports failing sources", api("GET", "/health", token=None)[1]["sources"]["failing"] >= 3)
    check("fetch failures are audited", any(x["event"] == "source_fetch_fail" for x in api("GET", "/audit?n=300")[1]))
    for sid in bad.values():
        api("DELETE", f"/sources/{sid}", {"actor": "alice"})

    urllib.request.urlopen(S + "/_ctl?nvd=down")
    s, r = api("POST", "/sources", {"name": "Late Feed", "url": S + "/feeds/late.xml", "type": "rss", "trust": "medium", "interval_minutes": 5})
    late = r["id"]
    wait_for(lambda: src_state(late).get("status") == "healthy", 40)
    time.sleep(1.5)
    lf = api("GET", "/vulns?cve=CVE-2026-70002")[1]
    check("NVD DOWN: finding and CVE id preserved", lf["total"] == 1 and lf["items"][0]["cve_ids"] == [sim.CVE_HOOLI])
    ld = api("GET", f"/vulns/{lf['items'][0]['id']}")[1] if lf["total"] else {}
    check("NVD DOWN: enrichment failure recorded honestly (no CVSS invented)", ld.get("nvd_status") == "unavailable" and ld.get("cvss") is None and ld.get("nvd_confirmed") is False,
          str({k: ld.get(k) for k in ("nvd_status", "cvss", "nvd_confirmed")}))
    urllib.request.urlopen(S + "/_ctl?nvd=ok")
    out = subprocess.run([sys.executable, "-c", "from pipeline import reenrich; print(reenrich.run())"], cwd=ROOT, env={**os.environ, **env, "PYTHONPATH": ROOT},
                         capture_output=True, text=True, timeout=120)
    time.sleep(1.5)
    ld = api("GET", f"/vulns/{lf['items'][0]['id']}")[1]
    check("NVD RECOVERED: re-enrichment fills CVSS 8.8 automatically", ld.get("cvss") == 8.8 and ld.get("nvd_confirmed") is True, f"{ld.get('cvss')} {out.stderr[-200:] if out.returncode else ''}")

    # ── optional browser phase ────────────────────────────────────────────────
    if opts.browser:
        section("6b. Real browser (Chromium via Playwright)")
        from scripts import browser_check
        for ok, name, detail in browser_check.run(f"http://127.0.0.1:{app_port}", TOKEN, S, shots=os.path.join(os.path.dirname(ROOT), "docs", "screenshots") if opts.screenshots else None):
            check(name, ok, detail)

    # ── 7. persistence across restart ─────────────────────────────────────────
    section("7. Restart: everything persists")
    counts = (api("GET", "/vulns")[1]["total"], len(api("GET", "/sources")[1]["sources"]))
    app.stop()
    app2 = App(env, ["--api-only"], app_port)
    api = app2.start()
    check("restart (api-only) works on existing data", bool(api))
    if api:
        check("findings and sources survive restart", (api("GET", "/vulns")[1]["total"], len(api("GET", "/sources")[1]["sources"])) == counts)
        d3 = api("GET", f"/vulns/{eid}")[1]
        check("analyst decision + notes survive restart", d3["analyst"]["status"] == "confirmed" and len(d3["analyst_history"]) == 3)
        check("enrichment (CVSS/EPSS/KEV) survives restart", d3["cvss"] == 9.8 and d3["epss"] == 0.74 and d3["kev"])
        check("audit log survives restart", any(x["event"] == "finding_confirmed" for x in api("GET", "/audit?n=1000")[1]))

    # ── 8. SSRF / input validation (separate instance WITHOUT the private-network override) ──
    section("8. Security: SSRF guard and validation (private targets NOT allowed)")
    env2 = {**env, "EVVP_ALLOW_PRIVATE_SOURCES": ""}
    app3 = App(env2, ["--api-only"], free_port())
    api3 = app3.start()
    if api3:
        for url in (S + "/feeds/news.xml", "http://localhost:9/x", "http://169.254.169.254/latest/meta-data/", "http://10.0.0.1/feed", "http://[::1]/feed", "file:///etc/passwd", "ftp://example.com/x"):
            s, r = api3("POST", "/sources/test", {"url": url, "type": "rss"})
            check(f"SSRF/scheme blocked on test: {url[:45]}", s == 422 and r["valid"] is False, f"{s} {r.get('error', '')[:60] if r else ''}")
        s, r = api3("POST", "/sources", {"name": "x", "url": "http://127.0.0.1:8000/api/health"})
        check("SSRF blocked on add", s == 400, str(r))
        check("duplicate URL / bad trust / bad interval rejected", (api3("POST", "/sources", {"name": "a", "url": "https://dup.example/f"})[0], api3("POST", "/sources", {"name": "b", "url": "https://dup.example/f"})[0],
              api3("POST", "/sources", {"name": "c", "url": "https://c.example/f", "trust": "ultra"})[0], api3("POST", "/sources", {"name": "d", "url": "https://d.example/f", "interval_minutes": 1})[0]) == (201, 400, 400, 400))
        check("SQL-ish / path-traversal input is inert", api3("GET", "/vulns?q=%27%3B%20DROP%20TABLE%20intel_raw%3B--")[0] == 200 and api3("GET", "/cves/..%2f..%2fetc%2fpasswd")[0] in (400, 404)
              and urllib.request.urlopen(f"http://127.0.0.1:{app3.port}/").status == 200)
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{app3.port}/ui/..%2f..%2f.env")
            traversal = False
        except urllib.error.HTTPError as e:
            traversal = e.code in (400, 404)
        check("static file path traversal blocked", traversal)
        app3.stop()
    else:
        check("security instance started", False)

    passed = sum(1 for r in RESULTS if r[0])
    failed = [r for r in RESULTS if not r[0]]
    print(f"\nRESULT: {passed} passed, {len(failed)} failed")
    for _, n, dt in failed:
        print(f"  FAILED: {n}  [{dt}]")
    if opts.keep and api:
        print(f"\nApp + simulator left running.\n  Dashboard: http://127.0.0.1:{app_port}   (API token: {TOKEN})\n  Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            pass
    app2.stop()
    if not opts.workdir and not opts.keep:
        shutil.rmtree(work, ignore_errors=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
