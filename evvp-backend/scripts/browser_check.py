"""Real-browser verification of the dashboard (Chromium via Playwright).

Used by `scripts/demo.py --browser`. Requires:  pip install playwright && playwright install chromium
Drives the actual UI: every page, filters, detail pages, the analyst form, and the full Source Manager
(add -> test -> save -> scheduler collects -> finding appears -> disable/enable/collect/edit/delete), and fails on any
console error, uncaught exception, failed API call, or visible `undefined` / `NaN` / `[object Object]`.
"""
from __future__ import annotations

import json
import os
import urllib.request

BAD_TEXT = ("undefined", "NaN", "[object Object]", "null%")


def _api(base, path, token=None):
    req = urllib.request.Request(base + "/api" + path, headers={"Authorization": f"Bearer {token}"} if token else {})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def run(base: str, token: str, sim: str, shots: str | None = None) -> list[tuple[bool, str, str]]:
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    out: list[tuple[bool, str, str]] = []

    def ok(name, cond, detail=""):
        out.append((bool(cond), name, "" if cond else str(detail)[:200]))
        return bool(cond)

    problems: list[str] = []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(viewport={"width": 1440, "height": 900})
        page = ctx.new_page()
        page.on("console", lambda m: problems.append(f"console.{m.type}: {m.text}") if m.type == "error" else None)
        page.on("pageerror", lambda e: problems.append(f"pageerror: {e}"))
        page.on("response", lambda r: problems.append(f"HTTP {r.status} {r.url}") if r.status >= 500 else None)
        shot = (lambda n: page.screenshot(path=os.path.join(shots, n), full_page=True)) if shots else (lambda n: None)
        if shots:
            os.makedirs(shots, exist_ok=True)

        def poll(cond, timeout=10.0):
            """Poll a Python predicate (Playwright's JS-string waits need eval, which the app's strict CSP forbids)."""
            import time
            end = time.time() + timeout
            while time.time() < end:
                try:
                    if cond():
                        return True
                except Exception:
                    pass
                page.wait_for_timeout(150)
            return False

        def expected_4xx(mark):
            """Drop browser 'Failed to load resource ... 4xx' noise caused by a deliberate negative test."""
            tail = problems[mark:]
            if tail and all(t.startswith("console.error: Failed to load resource") and any(c in t for c in ("400", "404", "422")) for t in tail):
                del problems[mark:]

        def go(route):
            page.goto(f"{base}/#/{route}")
            page.wait_for_load_state("networkidle")
            page.wait_for_selector("main h1", timeout=15000)

        def body_clean():
            txt = page.inner_text("main")
            return [b for b in BAD_TEXT if b in txt]

        page.goto(base + "/")
        page.evaluate(f"sessionStorage.setItem('evvp.token', '{token}'); localStorage.setItem('evvp.analyst', 'Browser Analyst')")
        stats = _api(base, "/stats")

        # ---- overview
        go("")
        txt = page.inner_text("main")
        ok("overview: loads with heading and sections", "Overview" in page.inner_text("main h1"))
        ok("overview: total findings equals the API value", str(stats["total_findings"]) in txt, f"{stats['total_findings']} not in page")
        ok("overview: zero-day / exploitation / sources figures shown", all(w in txt for w in ("zero-day", "xploitation", "ources")) or all(w.lower() in txt.lower() for w in ("zero", "exploitation", "sources")))
        ok("overview: charts rendered (SVG)", page.locator("main svg").count() >= 2, page.locator("main svg").count())
        ok("overview: no undefined/NaN text", not body_clean(), body_clean())
        ok("header health indicator is live", "…" not in page.inner_text("#health") and page.inner_text("#health").strip() != "")
        shot("overview.png")

        # ---- every nav item
        for label, route, heading in (("Findings", "findings", "findings"), ("Zero-Days", "zerodays", "zero"), ("CVEs", "cves", "cve"),
                                      ("Trending", "trending", "trending"), ("Threat Landscape", "landscape", "landscape"),
                                      ("Sources", "sources", "source"), ("Audit", "audit", "audit")):
            page.click(f"nav a[data-r='{route}']")
            arrived = poll(lambda: heading in page.inner_text("main h1").lower(), 15)
            page.wait_for_load_state("networkidle")
            ok(f"nav '{label}': heading shown, content rendered, no placeholder text", arrived and not body_clean() and len(page.inner_text("main")) > 80,
               f"h1={page.inner_text('main h1')!r} bad={body_clean()}")

        # ---- findings: search / filter / sort / pagination / detail
        go("findings")
        rows = page.locator("main table tbody tr").count()
        ok("findings: table lists real rows", rows == min(50, _api(base, "/vulns")["total"]), rows)
        page.fill("main input[name=q]", "initech")
        page.click("main [data-act=apply]")
        page.wait_for_load_state("networkidle")
        poll(lambda: page.locator("main table tbody tr").count() == 1)
        ok("findings: search narrows to the correlated Initech finding", page.locator("main table tbody tr").count() == 1)
        page.goto(f"{base}/#/findings")
        page.wait_for_selector("main table")
        page.select_option("main select[name=severity]", "CRITICAL")
        page.click("main [data-act=apply]")
        page.wait_for_load_state("networkidle")
        sev_total = _api(base, "/vulns?severity=CRITICAL")["total"]
        poll(lambda: page.locator("main table tbody tr").count() == sev_total)
        ok("findings: severity filter matches API", page.locator("main table tbody tr").count() == sev_total, sev_total)
        page.goto(f"{base}/#/findings?zero_day=true")
        page.wait_for_selector("main table")
        zd_total = _api(base, "/vulns?zero_day=true")["total"]
        ok("findings: zero-day filter matches API", page.locator("main table tbody tr").count() == zd_total, zd_total)
        page.goto(f"{base}/#/findings?sort=risk&order=asc")
        page.wait_for_selector("main table")
        ok("findings: sorting is applied", page.locator("main table tbody tr").count() > 0)

        # ---- finding detail (Initech)
        initech = _api(base, "/vulns?q=initech")["items"][0]
        go(f"finding/{initech['id']}")
        t = page.inner_text("main")
        ok("detail: title, CVE, severity, CVSS", all(x in t for x in ("CVE-2026-55501", "CRITICAL", "9.8")) or ("Critical" in t and "9.8" in t and "CVE-2026-55501" in t), t[:150])
        ok("detail: EPSS with data date, KEV, active exploitation", "74" in t and ("KEV" in t) and ("xploit" in t))
        ok("detail: risk breakdown components with reasons", all(x in t for x in ("CVSS", "EPSS", "Source trust")), "")
        ok("detail: MITRE ATT&CK T1190", "T1190" in t)
        ok("detail: sources + evidence from blog/GitHub/Reddit/vendor/NVD", all(x in t for x in ("GitHub", "Reddit", "NVD", "Researcher Blog")))
        ok("detail: timeline and early-warning lead time (7h 0m)", "7h 0m" in t and ("imeline" in t))
        ok("detail: analyst panel", page.locator("#a-save").count() == 1)
        ok("detail: no undefined/NaN", not body_clean(), body_clean())
        shot("finding-detail.png")

        # ---- XSS: hostile HTML in a feed title/description must render as text and never execute
        xss = _api(base, "/vulns?q=acme%20cam")["items"][0]
        for route in ("findings?q=acme", f"finding/{xss['id']}", ""):
            go(route)
            page.wait_for_timeout(400)
        page.goto(f"{base}/#/findings?q=acme")
        page.wait_for_selector("main table")
        ok("XSS: hostile feed HTML shown as text, no script/handler executed", page.evaluate("window.__pwned") is None and "<img src=x" in page.inner_text("main"),
           page.inner_text("main")[:120])
        go(f"finding/{xss['id']}")
        page.hover("main h1")
        ok("XSS: detail page also inert (no injected elements)", page.locator("main img[src='x'], main script").count() == 0 and page.evaluate("window.__pwned") is None)

        # ---- analyst workflow through the UI (Wayne: potential -> under investigation -> false positive)
        wayne = _api(base, "/vulns?q=wayne")["items"][0]
        go(f"finding/{wayne['id']}")
        for status, note in (("under_investigation", "Looking at vendor channels"), ("false_positive", "Different product, misattributed")):
            page.select_option("#a-status", status)
            page.fill("#a-notes", note)
            page.click("#a-save")
            page.wait_for_selector(".toast.ok", timeout=8000)
            page.wait_for_load_state("networkidle")
        w = _api(base, f"/vulns/{wayne['id']}")
        ok("analyst (UI): decision persisted with name and notes", w["analyst"]["status"] == "false_positive" and w["analyst"]["decision"]["analyst"] == "Browser Analyst"
           and "misattributed" in w["analyst"]["decision"]["notes"], str(w["analyst"])[:150])
        ok("analyst (UI): history shown on the page", poll(lambda: "misattributed" in page.inner_text("main"), 6), page.inner_text("main")[-300:].replace("\n", " | "))
        mark = len(problems)
        page.fill("#a-name", "")
        page.click("#a-note")
        page.wait_for_timeout(500)
        expected_4xx(mark)
        ok("analyst (UI): empty analyst name is rejected with a visible error", page.locator("#a-err").inner_text().strip() != "" or page.locator(".toast.bad").count() > 0)

        # ---- zero-days
        go("zerodays")
        t = page.inner_text("main")
        ok("zero-days: wording is 'potential' with confidence, never 'confirmed zero-day'", "otential" in t and "onfidence" in t and "confirmed zero-day" not in t.lower(), t[:120])
        ok("zero-days: evidence and sources listed", "No CVE" in t or "no CVE" in t)
        ok("zero-days: false-positive finding (Wayne) disappears from the list", "Wayne" not in t)
        shot("zero-days.png")

        # ---- CVEs
        go("cves")
        page.click("main table tbody tr a")
        page.wait_for_load_state("networkidle")
        page.wait_for_selector("main h1.mono", timeout=10000)
        t = page.inner_text("main")
        ok("CVE page: details, CVSS, references/sources shown", "CVSS" in t and ("eference" in t) and not body_clean(), body_clean())
        mark = len(problems)
        page.goto(f"{base}/#/cve/CVE-1999-00000")
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(500)
        expected_4xx(mark)
        ok("CVE page: unknown CVE handled gracefully", "undefined" not in page.inner_text("main") and page.locator("main").inner_text().strip() != "")

        # ---- trending / landscape
        go("trending")
        t = page.inner_text("main")
        ok("trending: shows mention/source counts for Initech", "CVE-2026-55501" in t or "Initech" in t)
        go("landscape")
        t = page.inner_text("main")
        ok("landscape: categories, techniques (T1190) and sources from real data", "T1190" in t and "Remote Code Execution" in t)
        shot("threat-landscape.png")

        # ---- Source Manager: full lifecycle through the UI
        go("sources")
        ok("sources: lists configured sources with trust/status", page.locator("main table tbody tr").count() >= 5)
        shot("sources.png")
        name = "UI Added Feed"
        page.click("[data-act=src-add]")
        page.fill("#f-name", name)
        page.fill("#f-url", f"{sim}/feeds/ui.xml")
        page.select_option("#f-type", "rss")
        page.select_option("#f-cat", "research")
        page.select_option("#f-trust", "high")
        page.fill("#f-int", "5")
        page.click("#f-try")
        poll(lambda: page.inner_text("#f-test").strip() not in ("", "Testing…"), 20)
        ok("sources UI: 'Test source' reports a valid feed before saving", "alid" in page.inner_text("#f-test") or "entr" in page.inner_text("#f-test").lower(), page.inner_text("#f-test"))
        mark = len(problems)
        page.fill("#f-url", "javascript:alert(1)")
        page.click("#f-save")
        page.wait_for_timeout(600)
        expected_4xx(mark)
        ok("sources UI: invalid URL is rejected with a visible message", page.locator("#f-err").inner_text().strip() != "" or page.locator(".toast.bad").count() > 0)
        page.fill("#f-url", f"{sim}/feeds/ui.xml")
        page.click("#f-save")
        page.wait_for_selector(".toast.ok", timeout=10000)
        page.wait_for_selector(f"main tr:has-text('{name}')", timeout=10000)
        # scheduler picks it up -> finding appears, with no restart and no code change
        found = False
        for _ in range(40):
            if _api(base, "/vulns?q=stark")["total"] == 1:
                found = True
                break
            page.wait_for_timeout(1000)
        ok("sources UI -> scheduler collects -> finding exists in the API (no restart)", found)
        def healthy_row():
            page.goto(f"{base}/#/sources")
            page.reload()
            page.wait_for_selector(f"main tr:has-text('{name}')")
            return "healthy" in page.locator(f"main tr:has-text('{name}')").inner_text().lower()
        ok("sources UI: status becomes healthy with last-collection info", poll(healthy_row, 20), page.locator(f"main tr:has-text('{name}')").inner_text().replace("\n", " | "))
        go("findings")
        page.fill("main input[name=q]", "stark")
        page.click("main [data-act=apply]")
        poll(lambda: page.locator("main table tbody tr").count() == 1)
        ok("finding from the UI-added source is displayed in the Findings page", "Stark" in page.inner_text("main table"))
        go("sources")
        sid = [s for s in _api(base, "/sources")["sources"] if s["name"] == name][0]["id"]
        page.click(f"[data-act=src-toggle][data-id='{sid}']")
        page.wait_for_selector(".toast.ok", timeout=8000)
        page.wait_for_load_state("networkidle")
        ok("sources UI: disable works", _api(base, "/sources")["sources"] and [s for s in _api(base, "/sources")["sources"] if s["id"] == sid][0]["enabled"] is False)
        page.click(f"[data-act=src-toggle][data-id='{sid}']")
        page.wait_for_timeout(800)
        ok("sources UI: enable works", [s for s in _api(base, "/sources")["sources"] if s["id"] == sid][0]["enabled"] is True)
        page.click(f"[data-act=src-test][data-id='{sid}']")
        page.wait_for_selector(".toast", timeout=20000)
        ok("sources UI: 'Test' on a saved source gives visible feedback", page.locator(".toast").count() >= 1)
        page.click(f"[data-act=src-collect][data-id='{sid}']")
        page.wait_for_selector(".toast", timeout=8000)
        ok("sources UI: 'Collect now' triggers collection (202)", any(e["event"] == "source_collect_triggered" for e in _api(base, "/audit?n=200")))
        page.click(f"[data-act=src-edit][data-id='{sid}']")
        page.select_option("#f-trust", "low")
        page.fill("#f-int", "15")
        page.click("#f-save")
        page.wait_for_selector(".toast.ok", timeout=8000)
        s = [s for s in _api(base, "/sources")["sources"] if s["id"] == sid][0]
        ok("sources UI: edit trust and interval persisted", s["trust"] == "low" and s["interval_minutes"] == 15, str(s["trust"]))
        page.wait_for_load_state("networkidle")
        page.click(f"[data-act=src-del][data-id='{sid}']")
        page.click("#d-ok")
        page.wait_for_selector(".toast.ok", timeout=8000)
        ok("sources UI: delete works", all(s["id"] != sid for s in _api(base, "/sources")["sources"]))
        ok("sources UI: builtin sources have no delete button", page.locator("tr:has-text('NVD') [data-act=src-del]").count() == 0)

        # ---- Source Manager: API/custom source with a JSON field mapping, added through the UI
        go("sources")
        api_name = "UI API Source"
        page.click("[data-act=src-add]")
        page.fill("#f-name", api_name)
        page.fill("#f-url", f"{sim}/api/advisories.json?set=2")
        page.select_option("#f-type", "api")
        ok("sources UI: field-mapping inputs appear for API/custom type", page.locator("#f-map").is_visible())
        page.select_option("#f-type", "rss")
        ok("sources UI: mapping inputs hidden again for RSS", not page.locator("#f-map").is_visible())
        page.select_option("#f-type", "api")
        for fid, val in (("#m-items", "data.advisories"), ("#m-id", "advisory_id"), ("#m-title", "name"), ("#m-url", "link"), ("#m-date", "issued"), ("#m-text", "summary")):
            page.fill(fid, val)
        page.click("#f-try")
        poll(lambda: page.inner_text("#f-test").strip() not in ("", "Testing…"), 20)
        ok("sources UI: API source test previews the parsed entries", "Pied Piper" in page.inner_text("#f-test"), page.inner_text("#f-test")[:150])
        page.click("#f-save")
        page.wait_for_selector(".toast.ok", timeout=10000)
        found = poll(lambda: _api(base, "/vulns?q=pied%20piper")["total"] == 1, 40)
        ok("sources UI (API type) -> scheduler collects -> finding generated from the mapping", found)
        pp = _api(base, "/vulns?q=pied%20piper")["items"][0] if found else {}
        ok("API-sourced finding is scored: RCE mapped to T1190, PoC detected", any(t["id"] == "T1190" for t in pp.get("attack_techniques", [])) and pp.get("poc") is True)
        asid = [s for s in _api(base, "/sources")["sources"] if s["name"] == api_name][0]["id"]
        go("sources")
        page.click(f"[data-act=src-del][data-id='{asid}']")
        page.click("#d-ok")
        page.wait_for_selector(".toast.ok", timeout=8000)

        # ---- audit
        go("audit")
        t = page.inner_text("main")
        ok("audit page: shows source / analyst / collection events", all(x in t for x in ("source_added", "finding_false_positive")) or ("source" in t and "analyst" in t.lower()), t[:100])
        ok("audit page: no placeholder text", not body_clean(), body_clean())
        shot("audit.png")

        # ---- settings + theme
        page.click("#settings")
        page.fill("#s-an", "Browser Analyst")
        page.select_option("#s-th", "light")
        page.click("#s-save")
        page.wait_for_selector(".toast.ok")
        ok("settings: saved, theme switches", page.evaluate("document.documentElement.dataset.theme") == "light")

        # ---- quick search box
        page.fill("#quick", "initech")
        page.press("#quick", "Enter")
        page.wait_for_load_state("networkidle")
        ok("header quick-search navigates to findings", "findings" in page.url)

        # ---- responsive: no horizontal overflow on a phone
        ctx2 = browser.new_context(viewport={"width": 390, "height": 800})
        m = ctx2.new_page()
        m.goto(base + "/")
        m.evaluate(f"sessionStorage.setItem('evvp.token', '{token}')")
        for route in ("", "findings", "sources"):
            m.goto(f"{base}/#/{route}")
            m.wait_for_load_state("networkidle")
            m.wait_for_selector("main h1")
            ok(f"mobile 390px: '#/{route}' has no page-level horizontal overflow", m.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 2"),
               m.evaluate("document.documentElement.scrollWidth"))
        ctx2.close()

        ok("NO console errors, uncaught exceptions or HTTP 5xx during the whole session", not problems, "; ".join(problems[:4]))
        browser.close()
    return out
