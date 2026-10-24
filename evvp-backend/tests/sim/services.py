"""Offline SIMULATOR of the external services EVVP talks to (NVD, EPSS, CISA KEV, GitHub, Reddit, RSS/Atom).

It exists so the *real* collector / HTTP / parsing code can be exercised end to end without internet access.
It is test infrastructure only: it is never used by the application, and its data lives only in memory.
It is NOT a substitute for testing against the live services (see README → Verification status).

Run:  python -m tests.sim.services --port 8900
Point EVVP at it with:  NVD_BASE_URL=http://127.0.0.1:8900/nvd EPSS_URL=http://127.0.0.1:8900/epss
   KEV_URL=http://127.0.0.1:8900/kev.json GITHUB_API_URL=http://127.0.0.1:8900/github REDDIT_BASE_URL=http://127.0.0.1:8900/reddit
Failure injection:  GET /_ctl?nvd=down|429|garbage|empty|ok   (also epss, kev, github, reddit)

Scenario (times relative to simulator start):  one vulnerability ("Initech Gateway") seen first by a researcher,
then a GitHub PoC, a Reddit thread, a vendor advisory that assigns CVE-2026-55501, and finally NVD — plus an
unrelated CVE (Globex), a different "Gateway" product that must NOT merge (Wayne), a no-CVE zero-day (Umbrella) and noise.
"""
from __future__ import annotations

import argparse
import json
import threading
import time
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

T0 = datetime.now(timezone.utc)
MODE = {"nvd": "ok", "epss": "ok", "kev": "ok", "github": "ok", "reddit": "ok"}
CVE_INITECH, CVE_GLOBEX, CVE_HOOLI = "CVE-2026-55501", "CVE-2026-60010", "CVE-2026-70002"


def at(hours_ago: float) -> datetime:
    return T0 - timedelta(hours=hours_ago)


def rfc(dt): return format_datetime(dt)
def iso(dt): return dt.isoformat().replace("+00:00", "Z")


# ── RSS / Atom ────────────────────────────────────────────────────────────────
def rss(title, items):
    body = "".join(f"<item><title>{t}</title><link>{l}</link><guid>{g}</guid><pubDate>{rfc(d)}</pubDate><description>{x}</description></item>"
                   for t, l, g, d, x in items)
    return f'<?xml version="1.0"?><rss version="2.0"><channel><title>{title}</title><link>http://sim.test</link>{body}</channel></rss>'.encode()


FEEDS = {
    "/feeds/researcher.xml": lambda: rss("Researcher Blog", [
        ("Initech Gateway unauthenticated RCE zero-day exploited in the wild", "http://sim.test/r/initech", "r-initech", at(9),
         "A researcher reports an unauthenticated remote code execution zero-day in Initech Gateway. Attackers are actively exploiting it; no patch or CVE yet."),
        ("Wayne Gateway unauthenticated RCE exploited in the wild", "http://sim.test/r/wayne", "r-wayne", at(6),
         "A different product: Wayne Gateway has an unauthenticated remote code execution flaw reported as exploited in the wild."),
        ("Our team picnic photos", "http://sim.test/r/picnic", "r-picnic", at(5), "Fun day out at the lake.")]),
    "/feeds/vendor.xml": lambda: rss("Initech Security Advisories", [
        (f"Initech Security Advisory IN-2026-001: Initech Gateway remote code execution ({CVE_INITECH})", "http://sim.test/v/in-2026-001", "v-1", at(5),
         f"Initech confirms {CVE_INITECH}, an unauthenticated remote code execution vulnerability in Initech Gateway. Fixed in 4.2.1.")]),
    "/feeds/news.xml": lambda: rss("Sim Security News", [
        (f"Globex Router flaw {CVE_GLOBEX} allows SQL injection", "http://sim.test/n/globex", "n-globex", at(4),
         f"Globex Router firmware is affected by SQL injection ({CVE_GLOBEX}). A PoC exploit is available."),
        ("Initech Gateway exploited in the wild, vendor confirms", "http://sim.test/n/initech", "n-initech", at(3),
         "News coverage of the Initech Gateway remote code execution attacks; the vendor advisory confirms active exploitation.")]),
    "/feeds/atom.xml": lambda: (f'<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><title>Sim Atom Feed</title><link href="http://sim.test"/>'
        f'<entry><title>Umbrella VPN zero-day privilege escalation PoC released</title><link href="http://sim.test/a/umbrella"/><id>a-umbrella</id>'
        f'<updated>{iso(at(2))}</updated><summary>A 0-day privilege escalation in Umbrella VPN with a public PoC exploit. No CVE has been assigned.</summary></entry></feed>').encode(),
    "/feeds/late.xml": lambda: rss("Late Feed", [
        (f"Hooli Switch {CVE_HOOLI} remote code execution exploited in the wild", "http://sim.test/l/hooli", "l-hooli", at(0.5),
         f"Hooli Switch firmware is affected by {CVE_HOOLI}, a remote code execution flaw reportedly exploited in the wild.")]),
    "/feeds/ui.xml": lambda: rss("Stark Feed", [
        ("Stark Router command injection vulnerability with public PoC exploit", "http://sim.test/u/stark", "u-stark", at(0.1),
         "Stark Router firmware contains an unauthenticated command injection vulnerability. A proof-of-concept exploit has been published.")]),
    "/feeds/xss.xml": lambda: rss("XSS Feed", [
        ("&lt;img src=x onerror=window.__pwned=1&gt; Acme Cam unauthenticated RCE zero-day exploited in the wild", "http://sim.test/x/acme", "x-acme", at(0.3),
         "Remote code execution zero-day exploited in the wild. &lt;script&gt;window.__pwned=2&lt;/script&gt; &lt;b onmouseover=window.__pwned=3&gt;hover&lt;/b&gt;")]),
    "/feeds/empty.xml": lambda: rss("Empty Feed", []),
    "/feeds/dup.xml": lambda: rss("Dup Feed", [("Duplicate Co firewall RCE zero-day exploited in the wild", "http://sim.test/d/1", "dup-1", at(1),
        "Remote code execution zero-day in Duplicate Co firewall exploited in the wild.")] * 3),
    "/feeds/malformed.xml": lambda: b"<rss><channel><title>broken",
    "/feeds/notafeed.html": lambda: b"<!DOCTYPE html><html><body>Not a feed</body></html>",
}


# ── NVD / EPSS / KEV ──────────────────────────────────────────────────────────
def nvd_record(cve, published, desc, score, sev, vendor, product):
    return {"cve": {"id": cve, "published": published.strftime("%Y-%m-%dT%H:%M:%S.000"), "lastModified": published.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "descriptions": [{"lang": "es", "value": "x"}, {"lang": "en", "value": desc}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score, "baseSeverity": sev, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
            "references": [{"url": f"https://vendor.example/{cve}"}, {"url": f"https://nvd.nist.gov/vuln/detail/{cve}"}],
            "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*"}]}]}]}}


NVD = {CVE_INITECH: nvd_record(CVE_INITECH, at(2), "Initech Gateway before 4.2.1 allows unauthenticated remote code execution.", 9.8, "CRITICAL", "initech", "gateway"),
       CVE_GLOBEX: nvd_record(CVE_GLOBEX, at(3.5), "SQL injection in Globex Router web UI.", 7.5, "HIGH", "globex", "router")}
NVD[CVE_HOOLI] = nvd_record(CVE_HOOLI, at(0.2), "Hooli Switch firmware allows remote code execution.", 8.8, "HIGH", "hooli", "switch")
EPSS = {CVE_HOOLI: (0.31, 0.92), CVE_INITECH: (0.74, 0.98), CVE_GLOBEX: (0.12, 0.81)}


def route(path, q):
    """Return (status, content_type, body, headers)."""
    J = "application/json"
    if path in FEEDS:
        return 200, "application/rss+xml", FEEDS[path](), {}
    if path == "/feeds/500":
        return 500, "text/plain", b"boom", {}
    if path == "/feeds/429":
        return 429, "text/plain", b"slow down", {"Retry-After": "60"}
    if path == "/feeds/slow":
        time.sleep(25); return 200, "application/rss+xml", rss("Slow", []), {}
    if path.startswith("/nvd"):
        m = MODE["nvd"]
        if m == "down": return 503, J, b'{"message":"unavailable"}', {}
        if m == "429": return 429, J, b'{"message":"rate limited"}', {}
        if m == "garbage": return 200, J, b"<<not json>>", {}
        if m == "empty": return 200, J, json.dumps({"totalResults": 0, "vulnerabilities": []}).encode(), {}
        if "cveId" in q:
            rec = NVD.get(q["cveId"][0].upper())
            return 200, J, json.dumps({"totalResults": 1 if rec else 0, "vulnerabilities": [rec] if rec else []}).encode(), {}
        recs = [r for c, r in NVD.items() if c != CVE_HOOLI]      # Hooli is only resolvable by id (published later in the scenario)
        start, per = int(q.get("startIndex", ["0"])[0]), int(q.get("resultsPerPage", ["2000"])[0])
        return 200, J, json.dumps({"resultsPerPage": per, "startIndex": start, "totalResults": len(recs), "vulnerabilities": recs[start:start + per]}).encode(), {}
    if path.startswith("/epss"):
        if MODE["epss"] == "down": return 503, J, b"{}", {}
        ids = [c.upper() for c in q.get("cve", [""])[0].split(",") if c]
        data = [{"cve": c, "epss": str(EPSS[c][0]), "percentile": str(EPSS[c][1]), "date": T0.strftime("%Y-%m-%d")} for c in ids if c in EPSS]
        return 200, J, json.dumps({"status": "OK", "total": len(data), "data": data}).encode(), {}
    if path == "/kev.json":
        if MODE["kev"] == "down": return 503, J, b"{}", {}
        today, due = T0.strftime("%Y-%m-%d"), (T0 + timedelta(days=21)).strftime("%Y-%m-%d")
        old = (T0 - timedelta(days=400)).strftime("%Y-%m-%d")
        entry = lambda cve, vendor, prod, name, desc, added: {"cveID": cve, "vendorProject": vendor, "product": prod, "vulnerabilityName": name, "shortDescription": desc,
                "requiredAction": "Apply updates per vendor instructions.", "dateAdded": added, "dueDate": due, "knownRansomwareCampaignUse": "Unknown"}
        return 200, J, json.dumps({"title": "sim KEV", "vulnerabilities": [
            entry(CVE_INITECH, "Initech", "Gateway", "Initech Gateway Remote Code Execution Vulnerability", "Initech Gateway allows unauthenticated remote code execution.", today),
            entry("CVE-2026-90001", "Soylent", "Print Server", "Soylent Print Server Authentication Bypass Vulnerability", "Soylent Print Server contains an authentication bypass.", today),
            entry("CVE-2019-00001", "Oldware", "Legacy", "Oldware Legacy Buffer Overflow Vulnerability", "A very old KEV entry that must be ignored by the lookback window.", old)]}).encode(), {}
    if path == "/api/advisories.json":
        n = q.get("set", ["1"])[0]
        adv = {"1": {"advisory_id": "ADV-1", "name": "Vandelay Appliance CVE-2026-81001 remote code execution exploited in the wild", "link": "http://sim.test/adv/1",
                     "issued": iso(at(1)), "summary": "Vandelay Appliance has a remote code execution flaw (CVE-2026-81001) that is exploited in the wild."},
               "2": {"advisory_id": "ADV-2", "name": "Pied Piper Compression Server unauthenticated RCE with public PoC exploit", "link": "http://sim.test/adv/2",
                     "issued": at(0.5).timestamp(), "summary": "A PoC exploit was published for an unauthenticated remote code execution vulnerability in Pied Piper Compression Server."}}[n]
        return 200, J, json.dumps({"data": {"advisories": [adv, {"advisory_id": "ADV-X", "name": "", "summary": "no title: must be skipped"}]}}).encode(), {}
    if path == "/api/notjson":
        return 200, "text/plain", b"definitely not json", {}
    if path.startswith("/github/search/"):
        if MODE["github"] == "down": return 502, J, b"{}", {}
        kind = path.rsplit("/", 1)[1]
        if kind == "repositories":
            items = [{"id": 9001, "full_name": "pwn-lab/initech-gateway-rce-poc", "description": "PoC exploit for Initech Gateway unauthenticated remote code execution",
                      "owner": {"login": "pwn-lab"}, "created_at": iso(at(8)), "updated_at": iso(at(1)), "html_url": "https://github.com/pwn-lab/initech-gateway-rce-poc",
                      "stargazers_count": 42, "forks_count": 7, "language": "Python", "topics": ["poc", "rce"]}]
        else:
            items = []
        return 200, J, json.dumps({"total_count": len(items), "items": items}).encode(), {}
    if path.startswith("/github/repos"):
        return 404, J, b"{}", {}
    if path.startswith("/reddit/r/") and path.endswith("/new.json"):
        if MODE["reddit"] == "down": return 503, J, b"{}", {}
        sub = path.split("/")[3]
        kids = [{"data": {"id": "sim1", "title": "Initech Gateway RCE being exploited - anyone seeing this?", "selftext": "Unauthenticated remote code execution against Initech Gateway, "
                "looks like it is being exploited in the wild. Patch status?", "author": "netsec_fan", "created_utc": at(7).timestamp(), "permalink": "/r/netsec/comments/sim1/",
                "score": 120, "num_comments": 33, "is_self": True}}] if sub == "netsec" else []
        return 200, J, json.dumps({"data": {"children": kids}}).encode(), {}
    return 404, "text/plain", b"not found", {}


class Handler(BaseHandler := BaseHTTPRequestHandler):
    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/_ctl":
            for k, v in q.items():
                if k in MODE: MODE[k] = v[0]
            return self._send(200, "application/json", json.dumps(MODE).encode(), {})
        try:
            self._send(*route(u.path, q))
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _send(self, status, ctype, body, headers):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in headers.items(): self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a): pass


def start(port: int = 8900) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True, name="evvp-sim").start()
    return srv


if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--port", type=int, default=8900); a = ap.parse_args()
    print(f"EVVP external-service simulator on http://127.0.0.1:{a.port}  (Ctrl+C to stop)")
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    try: srv.serve_forever()
    except KeyboardInterrupt: pass
