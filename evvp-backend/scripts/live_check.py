#!/usr/bin/env python3
"""EVVP LIVE verification — tests the REAL external services and the full pipeline with real data.

    python scripts/live_check.py              # real NVD, EPSS, CISA KEV, GitHub, Reddit, RSS feeds + JSON API (needs internet)
    python scripts/live_check.py --sim        # self-test of THIS script against the local simulator (no internet)
    python scripts/live_check.py --only nvd epss kev      # subset: nvd epss kev github reddit rss app

Each stage prints PASS / FAIL / BLOCKED:
    PASS     verified against the real service
    FAIL     the service answered but EVVP mishandled it (or the service rejected the request) -> a real problem
    BLOCKED  the network (proxy/firewall/offline) stopped the request; the stage is NOT verified
Exit code: 0 = everything PASS, 1 = at least one FAIL, 3 = no FAIL but something was BLOCKED/unverified.

Optional environment: GITHUB_TOKEN (recommended), NVD_API_KEY. Uses temporary directories; your data is never touched.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

RESULTS: list[tuple[str, str, str, str]] = []        # (stage, status, name, detail)
STAGE = ""


def rec(status: str, name: str, detail: str = "") -> bool:
    RESULTS.append((STAGE, status, name, detail))
    print(f"  {status:8} {name}" + (f"   ({detail})" if detail else ""), flush=True)
    return status == "PASS"


def check(name: str, cond: bool, detail: str = "") -> bool:
    return rec("PASS" if cond else "FAIL", name, "" if cond else detail if detail else "")


def stage(name: str) -> None:
    global STAGE
    STAGE = name
    print(f"\n=== {name}", flush=True)


def probe(url: str) -> tuple[str, str]:
    """Classify reachability: ('ok'|'blocked'|'rejected', detail)."""
    import requests
    try:
        r = requests.get(url, timeout=12, headers={"User-Agent": "EVVP-live-check/2.0"})
    except requests.RequestException as exc:
        return "blocked", f"{exc.__class__.__name__}"
    if r.headers.get("x-deny-reason"):
        return "blocked", f"egress policy: {r.headers['x-deny-reason']}"
    if r.status_code in (403, 429) and "text/plain" in r.headers.get("content-type", "") and len(r.content) < 200 and not r.headers.get("server"):
        return "blocked", f"HTTP {r.status_code} (looks like a proxy denial)"
    if r.status_code >= 400:
        return "rejected", f"HTTP {r.status_code}"
    return "ok", f"HTTP {r.status_code}"


def gate(url: str, label: str) -> bool:
    """True when the service is reachable; otherwise record BLOCKED/FAIL and return False."""
    state, detail = probe(url)
    if state == "ok":
        rec("PASS", f"{label} reachable", detail)
        return True
    rec("BLOCKED" if state == "blocked" else "FAIL", f"{label} reachable", detail)
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sim", action="store_true", help="use the local simulator (self-test of this script)")
    ap.add_argument("--only", nargs="*", default=[], choices=["nvd", "epss", "kev", "github", "reddit", "rss", "app"])
    opts = ap.parse_args()
    want = lambda s: not opts.only or s in opts.only          # noqa: E731

    work = tempfile.mkdtemp(prefix="evvp-live-")
    env = {"EVVP_RAW_DATA_DIR": f"{work}/raw", "EVVP_DATA_DIR": f"{work}/data", "EVVP_LOG_DIR": f"{work}/logs", "DB_URL": "",
           "EVVP_API_TOKEN": "", "GITHUB_REQUESTS_PER_HOUR": "400"}
    if opts.sim:
        from tests.sim import services as sim
        port = 0
        import socket
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        sim.start(port)
        S = f"http://127.0.0.1:{port}"
        env.update(NVD_BASE_URL=f"{S}/nvd", EPSS_URL=f"{S}/epss", KEV_URL=f"{S}/kev.json", GITHUB_API_URL=f"{S}/github", REDDIT_BASE_URL=f"{S}/reddit",
                   EVVP_ALLOW_PRIVATE_SOURCES="1", GITHUB_TOKEN="", NVD_API_KEY="", NVD_MIN_INTERVAL_SECONDS="0")
        T = {"cve": sim.CVE_INITECH, "cvss": 9.8, "epss": 0.5, "word": "Initech", "kev": True, "min_feed": 1,
             "rss": [(f"{S}/feeds/researcher.xml", "Sim researcher"), (f"{S}/feeds/news.xml", "Sim news"), (f"{S}/feeds/atom.xml", "Sim atom")],
             "api": (f"{S}/api/advisories.json", {"items_path": "data.advisories", "id_field": "advisory_id", "title_field": "name", "url_field": "link", "date_field": "issued", "text_field": "summary"}),
             "urls": {"nvd": f"{S}/nvd?cveId={sim.CVE_INITECH}", "epss": f"{S}/epss?cve={sim.CVE_INITECH}", "kev": f"{S}/kev.json", "github": f"{S}/github/search/repositories?q=x",
                      "reddit": f"{S}/reddit/r/netsec/new.json"}, "github_kw": "initech gateway", "tick": "2"}
        print(f"MODE: simulator self-test ({S}) — this does NOT verify the live services")
    else:
        T = {"cve": "CVE-2021-44228", "cvss": 9.0, "epss": 0.5, "word": "Log4j", "kev": True, "min_feed": 1,
             "rss": [("https://www.bleepingcomputer.com/feed/", "BleepingComputer"), ("https://krebsonsecurity.com/feed/", "KrebsOnSecurity"),
                     ("https://googleprojectzero.blogspot.com/feeds/posts/default", "Project Zero (Atom)")],
             "api": ("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                     {"items_path": "vulnerabilities", "id_field": "cveID", "title_field": "vulnerabilityName", "date_field": "dateAdded", "text_field": "shortDescription"}),
             "urls": {"nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228", "epss": "https://api.first.org/data/v1/epss?cve=CVE-2021-44228",
                      "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "github": "https://api.github.com/rate_limit",
                      "reddit": "https://www.reddit.com/r/netsec/new.json?limit=1"}, "github_kw": "CVE-2021-44228", "tick": "2"}
        print("MODE: LIVE internet")
    os.environ.update(env)
    from datetime import datetime, timezone

    # ── NVD ───────────────────────────────────────────────────────────────────
    if want("nvd"):
        stage("NVD (real API)")
        if gate(T["urls"]["nvd"], "NVD API"):
            from pipeline import nvd_enricher
            try:
                r = nvd_enricher._fetch_cve(T["cve"])
            except Exception as exc:
                r = None
                rec("FAIL", "NVD lookup", str(exc)[:150])
            if r:
                check("CVE record returned for " + T["cve"], r["cve_id"] == T["cve"])
                check("description present" + (f" and mentions {T['word']}" if not opts.sim else ""), bool(r["description"]) and (opts.sim or T["word"].lower() in r["description"].lower()), r["description"][:80])
                check("CVSS v3 score/severity/vector parsed", (r["cvss_v3"].get("score") or 0) >= T["cvss"] and r["cvss_v3"].get("severity") and r["cvss_v3"].get("vector"), str(r["cvss_v3"]))
                check("references present", len(r["references"]) >= 1)
                check("published and modified dates parse", all(datetime.fromisoformat(r[k].replace("Z", "+00:00")) for k in ("published", "modified")), str((r["published"], r["modified"])))
                item = nvd_enricher.enrich({"title": f"Test mention of {T['cve']}", "text": ""})
                check("enrich() sets nvd_status=ok and keeps the CVE", item["nvd_status"] == "ok" and item["cve_ids"] == [T["cve"]], str(item.get("nvd_status")))
            nf = nvd_enricher.enrich({"title": "CVE-2999-99999 does not exist", "text": ""})
            check("unknown CVE -> status not_found, CVE id preserved (no crash)", nf["nvd_status"] == "not_found" and nf["cve_ids"] == ["CVE-2999-99999"], str(nf.get("nvd_status")))

    # ── EPSS ──────────────────────────────────────────────────────────────────
    if want("epss"):
        stage("EPSS (real API)")
        if gate(T["urls"]["epss"], "EPSS API"):
            from pipeline.epss import enrich_epss
            it = enrich_epss({"cve_ids": [T["cve"]]})
            check("EPSS score and percentile returned", it.get("epss") is not None and 0 <= it["epss"] <= 1 and it.get("epss_percentile") is not None, str(it))
            check(f"EPSS plausible for this CVE (>= {T['epss']})", (it.get("epss") or 0) >= T["epss"], str(it.get("epss")))
            d = (it.get("epss_data") or [{}])[0].get("date")
            fresh = False
            try:
                fresh = (datetime.now(timezone.utc) - datetime.fromisoformat(d).replace(tzinfo=timezone.utc)).days <= 10
            except Exception:
                pass
            check("EPSS data date present and fresh (<= 10 days old)", fresh, str(d))
            check("unknown CVE yields no invented EPSS value", "epss" not in enrich_epss({"cve_ids": ["CVE-2999-99999"]}))

    # ── CISA KEV ──────────────────────────────────────────────────────────────
    if want("kev"):
        stage("CISA KEV (real catalog)")
        if gate(T["urls"]["kev"], "CISA KEV catalog"):
            from pipeline import kev, risk
            ids = kev._load()
            check("catalog loaded", len(ids) >= (1 if opts.sim else 1000), f"{len(ids)} entries")
            it = kev.enrich_kev({"cve_ids": [T["cve"]], "title": "x", "text": ""})
            check(f"{T['cve']} flagged as KEV with dates", bool(it.get("kev")) == T["kev"] and (not T["kev"] or it["kev"][0].get("added")), str(it.get("kev")))
            check("KEV flag => active exploitation in risk engine, with a 'CISA KEV' risk component", risk.active_exploitation(it) and any(p["factor"] == "CISA KEV" for p in risk.risk_breakdown(it)))
            check("CVE not in KEV is not flagged", "kev" not in kev.enrich_kev({"cve_ids": ["CVE-2999-99999"]}))
            from source_manager import manager
            from ingestion import cisa
            from storage import db
            manager.update_source("builtin-cisa-kev", {"enabled": True})
            cisa.run_once(force=True)
            st = manager.get_source("builtin-cisa-kev")
            check("CISA collector ran (recent entries ingested through the pipeline)", st["status"] == "healthy", str(st.get("last_error")))
            print(f"           KEV collector: {st['last_item_count']} entries inside the lookback window, {st['total_collected']} new findings stored")
            saved = [i for i in db.load_recent_raw(0) if i.get("platform") == "cisa"]
            check("KEV findings carry kev data + authoritative trust", all(i.get("kev") and i.get("source_trust") == "authoritative" for i in saved), f"{len(saved)} stored")

    # ── GitHub ────────────────────────────────────────────────────────────────
    if want("github"):
        stage("GitHub (real API)")
        print(f"  token configured: {bool(os.getenv('GITHUB_TOKEN'))}")
        if gate(T["urls"]["github"], "GitHub API"):
            from ingestion import github
            from storage import db
            before = len(db.load_recent_raw(0))
            try:
                github._search_repos(T["github_kw"])
                github._search_issues(T["github_kw"])
                rec("PASS", "repository + issue search executed without error")
            except Exception as exc:
                rec("FAIL", "GitHub search", str(exc)[:200])
            after = [i for i in db.load_recent_raw(0) if i.get("platform") == "github"]
            print(f"           stored GitHub items: {len(after)} (items that pass the signal filter; new total {len(db.load_recent_raw(0)) - before})")
            check("stored GitHub items are normalised (id, url, title, timestamp, trust)", all(i.get("id") and i.get("url") and i.get("title") and i.get("source_trust") for i in after))
            ev = sum(1 for i in db.load_recent_raw(0) for x in (i.get("sources") or []) if x.get("platform") == "github" and x.get("url") != i.get("url"))
            check("GitHub produced findings or evidence (items folded into an existing finding count as evidence)", len(after) + ev >= 1,
                  "nothing passed the security-signal filter — inspect the logs; unusual for a well-known CVE query")

    # ── Reddit ────────────────────────────────────────────────────────────────
    if want("reddit"):
        stage("Reddit (real)")
        if gate(T["urls"]["reddit"], "Reddit"):
            from ingestion import reddit
            ok = False
            for fn in (reddit._fetch_json, reddit._fetch_rss):
                try:
                    res = fn("netsec")
                    rec("PASS", f"{fn.__name__.strip('_')} collected r/netsec", str(res))
                    ok = True
                    break
                except Exception as exc:
                    rec("INFO", f"{fn.__name__.strip('_')} failed", str(exc)[:120])
            if not ok:
                rec("FAIL", "Reddit collection (JSON and RSS both failed)", "Reddit often blocks unauthenticated datacenter IPs; try from another network")

    # ── RSS / Atom ────────────────────────────────────────────────────────────
    if want("rss"):
        stage("RSS / Atom feeds (real)")
        from ingestion import blog
        from source_manager import manager
        from storage import db
        for url, name in T["rss"]:
            if not gate(url, name):
                continue
            src = manager.add_source({"name": name, "url": url, "type": "rss", "category": "news", "trust": "medium", "interval_minutes": 30})
            fetched, saved = blog.collect_source(src)
            st = manager.get_source(src["id"])
            check(f"{name}: collected and parsed", st["status"] == "healthy" and fetched > 0, f"{st.get('last_error')} fetched={fetched}")
            items = [i for i in db.load_recent_raw(0) if (i.get("metadata") or {}).get("source_id") == src["id"]]
            check(f"{name}: stored items have title, http URL, description, timestamp", all(i["title"] and i["url"].startswith("http") and i.get("timestamp") for i in items), f"{len(items)} items")
            print(f"           {name}: {fetched} entries, {saved} passed the security-signal filter")
            f2, s2 = blog.collect_source(manager.get_source(src["id"]))
            check(f"{name}: second collection stores no duplicates", s2 == 0, f"saved {s2}")

    # ── full live pipeline through the running app + dashboard API ────────────
    if want("app"):
        stage("Full live pipeline through the running application (Source Manager, real sources)")
        from scripts.demo import App, free_port, wait_for, Api
        probe_url = T["rss"][0][0]
        if not gate(probe_url, "RSS source for the app test"):
            rec("BLOCKED", "full live pipeline not exercised")
        else:
            app_env = {**env, "EVVP_TICK_SECONDS": T["tick"], "EVVP_CACHE_TTL": "1", "EVVP_API_TOKEN": "live-token"}
            shutil.rmtree(f"{work}/raw", ignore_errors=True)
            os.makedirs(f"{work}/data", exist_ok=True)
            json.dump([], open(f"{work}/data/sources.json", "w"))
            from source_manager.manager import BUILTINS
            json.dump([{**b, "enabled": True, "builtin": True} for b in BUILTINS], open(f"{work}/data/sources.json", "w"))
            app = App(app_env, [], free_port())
            api = app.start()
            if not api:
                rec("FAIL", "application started", open(app.log.name).read()[-500:])
            else:
                A = lambda m, p, b=None: api(m, p, b, token="live-token")      # noqa: E731
                rss_url, rss_name = T["rss"][0]
                s, r = A("POST", "/sources/test", {"url": rss_url, "type": "rss"})
                check("Source Manager: real RSS source test passes", s == 200 and r["entry_count"] > 0, str(r)[:120])
                s, rs = A("POST", "/sources", {"name": "Live RSS", "url": rss_url, "type": "rss", "category": "news", "trust": "medium", "interval_minutes": 5, "actor": "live-check"})
                check("Source Manager: add real RSS source", s == 201)
                api_url, mapping = T["api"]
                s, r = A("POST", "/sources/test", {"url": api_url, "type": "api", "mapping": mapping})
                check("Source Manager: real JSON/API source test previews entries", s == 200 and r["entry_count"] > 0, str(r)[:150])
                s, ra = A("POST", "/sources", {"name": "Live JSON API", "url": api_url, "type": "api", "category": "official", "trust": "authoritative", "interval_minutes": 5, "mapping": mapping, "actor": "live-check"})
                check("Source Manager: add real JSON/API source with field mapping", s == 201 and ra.get("collectable"))
                state = lambda sid: next((x for x in A("GET", "/sources")[1]["sources"] if x["id"] == sid), {})   # noqa: E731
                for sid, label in ((rs["id"], "RSS"), (ra["id"], "JSON API")):
                    check(f"{label} source collected automatically by the scheduler", bool(wait_for(lambda sid=sid: state(sid).get("status") == "healthy", 90)), str(state(sid).get("last_error")))
                # let the built-in collectors (NVD, CISA, GitHub, Reddit) run once as well
                time.sleep(20)
                s, v = A("GET", "/vulns?per_page=200")
                items = v["items"] if s == 200 else []
                check("findings appear in the dashboard API", len(items) > 0, f"{s} total={v.get('total') if v else None}")
                print(f"           findings: {len(items)}; with CVE: {sum(1 for i in items if i['cve_ids'])}; zero-day candidates: {sum(1 for i in items if i['zero_day_candidate'])}; "
                      f"KEV: {sum(1 for i in items if i.get('kev'))}; with EPSS: {sum(1 for i in items if i.get('epss') is not None)}; with CVSS: {sum(1 for i in items if i.get('cvss') is not None)}")
                cve_items = [i for i in items if i["cve_ids"]]
                if cve_items:
                    wait_for(lambda: any(A("GET", f"/vulns/{i['id']}")[1].get("nvd_confirmed") for i in cve_items[:15]), 60)
                    det = [A("GET", f"/vulns/{i['id']}")[1] for i in cve_items[:15]]
                    check("real CVEs were enriched by live NVD (NVD record + CVSS present)", any(d.get("nvd_confirmed") and d.get("cvss") for d in det),
                          str([(d["cve_ids"][:1], d.get("nvd_confirmed"), d.get("nvd_status")) for d in det][:5]))
                    check("CVEs that NVD does not have are reported honestly (nvd_status), never given invented CVSS", all(d.get("cvss") is None for d in det if not d.get("nvd_confirmed")))
                    d0 = max(det, key=lambda d: d["risk_score"])
                    check("risk breakdown is built from real components and sums to the score", min(100, sum(p["points"] for p in d0["risk_breakdown"])) == d0["risk_score"] and len(d0["risk_breakdown"]) >= 2, str(d0["risk_breakdown"]))
                    check("timeline and lead-time structure present", bool(d0["timeline"]["events"]) and d0["lead_time"].get("status"))
                    s, e = A("POST", f"/vulns/{d0['id']}/review", {"status": "under_investigation", "analyst": "live-check", "notes": "live verification"})
                    check("analyst decision on a real finding is recorded", s == 201 and A("GET", f"/vulns/{d0['id']}")[1]["analyst"]["status"] == "under_investigation")
                check("audit trail has source_added / source_collected / analyst events", {"source_added", "source_collected", "finding_reviewed"} <= {x["event"] for x in A("GET", "/audit?n=1000")[1]} or not cve_items,
                      str(sorted({x["event"] for x in A("GET", "/audit?n=1000")[1]})[:12]))
                # disable -> collection stops; enable -> resumes
                A("PATCH", f"/sources/{rs['id']}", {"enabled": False, "actor": "live-check"})
                lf = state(rs["id"]).get("last_fetched")
                time.sleep(8)
                check("disabled source is NOT collected any more", state(rs["id"]).get("last_fetched") == lf and A("POST", f"/sources/{rs['id']}/collect", {})[0] == 400)
                A("PATCH", f"/sources/{rs['id']}", {"enabled": True, "actor": "live-check"})
                A("POST", f"/sources/{rs['id']}/collect", {"actor": "live-check"})
                check("re-enabled source resumes collection", bool(wait_for(lambda: state(rs["id"]).get("last_fetched") != lf, 60)))
                s, st = A("GET", "/stats")
                check("dashboard statistics reflect live data", st["total_findings"] == v["total"] and st["sources"]["enabled"] >= 3, str(st["sources"]))
            app.stop()

    shutil.rmtree(work, ignore_errors=True)
    print("\n=== SUMMARY")
    by: dict[str, dict[str, int]] = {}
    for stg, status, _, _ in RESULTS:
        by.setdefault(stg, {}).setdefault(status, 0)
        by[stg][status] += 1
    for stg, c in by.items():
        overall = "FAIL" if c.get("FAIL") else "BLOCKED" if c.get("BLOCKED") else "PASS"
        print(f"  {overall:8} {stg}   {dict(c)}")
    fails = [r for r in RESULTS if r[1] == "FAIL"]
    blocked = [r for r in RESULTS if r[1] == "BLOCKED"]
    for r in fails:
        print(f"  FAILED: [{r[0]}] {r[2]}  ({r[3]})")
    if opts.sim:
        print("\nSIMULATOR SELF-TEST ONLY: a pass here proves this script works, NOT that the live services work.")
    print(f"\nRESULT: {sum(1 for r in RESULTS if r[1] == 'PASS')} passed, {len(fails)} failed, {len(blocked)} blocked-by-network")
    return 1 if fails else (3 if blocked else 0)


if __name__ == "__main__":
    sys.exit(main())
