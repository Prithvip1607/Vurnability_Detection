import json
import os
import unittest
from unittest import mock

from tests import helpers
import requests

RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>Test Feed</title><link>https://feed.test</link>
<item><title>Acme Gateway unauthenticated RCE zero-day exploited in the wild</title><link>https://feed.test/1</link>
<guid>1</guid><pubDate>Thu, 03 Sep 2026 10:00:00 +0000</pubDate>
<description>&lt;p&gt;Researchers released a PoC for an unauthenticated remote code execution flaw.&lt;/p&gt;</description></item>
<item><title>Company picnic photos</title><link>https://feed.test/2</link><guid>2</guid>
<pubDate>Thu, 03 Sep 2026 11:00:00 +0000</pubDate><description>Fun day out.</description></item>
</channel></rss>"""


class FakeResp:
    def __init__(self, content=b"", status=200, headers=None):
        self.content, self.status_code, self.headers = content, status, headers or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")


def _stub_pipeline():
    import pipeline.processor as proc
    return [
        mock.patch.object(proc, "enrich", lambda item: {**item, "nvd_data": [], "cve_ids": item.get("cve_ids", [])}),
        mock.patch.object(proc, "enrich_epss", lambda item: item),
        mock.patch.object(proc, "generate_summary", lambda item: ""),
        mock.patch.object(proc, "dispatch", lambda *a, **k: None),
        mock.patch.object(proc, "verify", lambda item, cross_source_count=1: {
            "verification_status": "likely", "credibility_score": 50, "poc_found": False, "cross_source_count": 1,
            "raw_id": item["id"], "poc_signals": [], "affected_products": [], "credibility_notes": [],
            "in_nvd": False, "in_nvd_at": ""}),
    ]


class CollectorTests(unittest.TestCase):
    def setUp(self):
        helpers.reset_files()
        self.patches = _stub_pipeline()
        for p in self.patches:
            p.start()
        import pipeline.processor as proc
        proc._recent_cache = []
        proc._cache_counter = 1
        from source_manager import manager
        self.m = manager
        self.src = manager.add_source({"name": "Test Feed", "url": "https://feed.test/rss", "type": "rss",
                                       "category": "research", "trust": "high", "interval_minutes": 15})

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def test_valid_feed_collected_and_source_marked_healthy(self):
        from ingestion import blog
        with mock.patch("ingestion.blog.requests.get", return_value=FakeResp(RSS)):
            fetched, saved = blog.collect_source(self.src)
        self.assertEqual((fetched, saved), (2, 1))                 # noise item dropped by signal filter
        s = self.m.get_source(self.src["id"])
        self.assertEqual(s["status"], "healthy")
        self.assertEqual(s["last_item_count"], 2)
        self.assertIsNotNone(s["last_success"])
        from storage.db import load_recent_raw
        items = load_recent_raw(days=0)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["metadata"]["source_trust"], "high")
        self.assertEqual(items[0]["source_trust"], "high")          # trust flows into scoring
        self.assertGreater(items[0]["intelligence"]["risk_score"], 0)
        self.assertTrue(items[0]["intelligence"]["zero_day_candidate"])

    def test_failures_are_isolated_and_recorded(self):
        from ingestion import blog
        for bad in (FakeResp(b"<html><body>nope</body></html>"), FakeResp(b"<rss><broken"), FakeResp(b"", 500)):
            with mock.patch("ingestion.blog.requests.get", return_value=bad):
                self.assertEqual(blog.collect_source(self.src), (0, 0))   # never raises
            s = self.m.get_source(self.src["id"])
            self.assertEqual(s["status"], "error")
            self.assertTrue(s["last_error"])
        with mock.patch("ingestion.blog.requests.get", side_effect=requests.ConnectionError("down")):
            self.assertEqual(blog.collect_source(self.src), (0, 0))
        self.assertGreaterEqual(self.m.get_source(self.src["id"])["consecutive_failures"], 4)

    def test_one_bad_source_does_not_stop_the_others(self):
        from ingestion import blog
        good = self.m.add_source({"name": "Good", "url": "https://good.test/rss", "type": "rss"})
        for s in self.m.list_sources():
            if s["id"] not in (self.src["id"], good["id"]):
                self.m.update_source(s["id"], {"enabled": False})

        def fake_get(url, **kw):
            if "feed.test" in url:
                raise requests.Timeout("slow")
            return FakeResp(RSS.replace(b"feed.test", b"good.test"))
        with mock.patch("ingestion.blog.requests.get", side_effect=fake_get):
            blog.run_once(force=True)
        self.assertEqual(self.m.get_source(self.src["id"])["status"], "error")
        self.assertEqual(self.m.get_source(good["id"])["status"], "healthy")

    def test_due_respects_interval_and_backoff(self):
        s = dict(self.m.get_source(self.src["id"]))
        self.assertTrue(self.m.due(s))
        self.m.mark_fetch(s["id"], success=True)
        self.assertFalse(self.m.due(self.m.get_source(s["id"])))
        disabled = self.m.update_source(s["id"], {"enabled": False})
        self.assertNotIn(disabled["id"], [x["id"] for x in self.m.enabled_feeds()])

    def test_cve_not_lost_when_nvd_unavailable(self):
        from pipeline import nvd_enricher
        item = {"title": "Bug CVE-2026-4242 exploited", "text": ""}
        with mock.patch.object(nvd_enricher, "_fetch_cve", side_effect=requests.ConnectionError("nvd down")), \
             mock.patch.object(nvd_enricher.time, "sleep"):
            out = nvd_enricher.enrich(item)
        self.assertEqual(out["cve_ids"], ["CVE-2026-4242"])
        self.assertEqual(out["nvd_status"], "unavailable")
        self.assertEqual(out["nvd_data"], [])


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        helpers.reset_files()
        from api import server
        cls.server = server
        cls.c = server.app.test_client()

    def setUp(self):
        helpers.reset_files()
        self.server.invalidate()
        os.environ.pop("EVVP_API_TOKEN", None)

    def _seed_item(self):
        from datetime import datetime, timedelta, timezone
        from email.utils import format_datetime
        from storage.db import save_raw
        published = datetime.now(timezone.utc) - timedelta(hours=2)        # relative: the test must not rot with the calendar
        save_raw({"id": "blog_t1", "platform": "blog", "source": "https://feed.test", "title": "Acme unauthenticated RCE zero-day exploited",
                  "text": "PoC exploited in the wild", "url": "https://feed.test/1", "timestamp": format_datetime(published),
                  "collected_at": (published + timedelta(minutes=5)).isoformat(), "signal_score": 28, "cve_ids": [], "nvd_data": [],
                  "source_trust": "high", "source_trust_weight": 80, "metadata": {"source_name": "Test Feed"}})
        self.server.invalidate()

    def test_core_endpoints_ok_on_empty_and_seeded_data(self):
        for u in ("/api/health", "/api/stats", "/api/vulns", "/api/cves", "/api/zerodays", "/api/trending",
                  "/api/threat-landscape", "/api/audit", "/api/audit/stats", "/api/sources", "/api/feed/all"):
            self.assertEqual(self.c.get(u).status_code, 200, u)
        self._seed_item()
        stats = self.c.get("/api/stats").get_json()
        self.assertEqual(stats["total_findings"], 1)
        self.assertEqual(stats["potential_zero_days"], 1)
        self.assertEqual(stats["active_exploitation"], 1)
        zd = self.c.get("/api/zerodays").get_json()["items"][0]
        self.assertTrue(zd["zero_day_evidence"])
        detail = self.c.get(f"/api/vulns/{zd['id']}").get_json()
        self.assertTrue(detail["risk_breakdown"])
        self.assertEqual(detail["analyst"]["status"], "potential")

    def test_validation_and_status_codes(self):
        self._seed_item()
        self.assertEqual(self.c.get("/api/vulns?severity=BOGUS").status_code, 400)
        self.assertEqual(self.c.get("/api/vulns?min_risk=x").status_code, 400)
        self.assertEqual(self.c.get("/api/vulns?sort=nope").status_code, 400)
        self.assertEqual(self.c.get("/api/vulns/ent-missing").status_code, 404)
        self.assertEqual(self.c.get("/api/cves/not-a-cve").status_code, 400)
        self.assertEqual(self.c.get("/api/cves/CVE-2026-0001").status_code, 404)
        self.assertEqual(self.c.get("/api/feed/bogus").status_code, 400)
        self.assertEqual(self.c.delete("/api/vulns").status_code, 405)
        self.assertIn("error", self.c.get("/api/nope").get_json())

    def test_filters_and_pagination(self):
        self._seed_item()
        self.assertEqual(self.c.get("/api/vulns?zero_day=true").get_json()["total"], 1)
        self.assertEqual(self.c.get("/api/vulns?zero_day=false").get_json()["total"], 0)
        self.assertEqual(self.c.get("/api/vulns?q=acme").get_json()["total"], 1)
        self.assertEqual(self.c.get("/api/vulns?q=zzzz").get_json()["total"], 0)
        self.assertEqual(self.c.get("/api/vulns?source=test feed").get_json()["total"], 1)
        self.assertEqual(self.c.get("/api/vulns?per_page=1&page=9").get_json()["page"], 1)

    def test_source_manager_crud_and_validation(self):
        r = self.c.post("/api/sources", json={"name": "SecurityWeek2", "url": "https://example.test/feed", "type": "rss",
                                              "category": "news", "trust": "medium", "interval_minutes": 30})
        self.assertEqual(r.status_code, 201)
        sid = r.get_json()["id"]
        self.assertEqual(self.c.post("/api/sources", json={"name": "dup", "url": "https://example.test/feed"}).status_code, 400)
        for bad in ({"name": "", "url": "https://a.test"}, {"name": "x", "url": "ftp://a.test"},
                    {"name": "x", "url": "https://a.test", "trust": "super"},
                    {"name": "x", "url": "https://a.test", "interval_minutes": 1},
                    {"name": "x", "url": "https://a.test", "type": "carrier-pigeon"}):
            self.assertEqual(self.c.post("/api/sources", json=bad).status_code, 400, bad)
        r = self.c.patch(f"/api/sources/{sid}", json={"enabled": False, "trust": "low", "interval_minutes": 60})
        self.assertEqual(r.status_code, 200)
        self.assertEqual((r.get_json()["enabled"], r.get_json()["trust"]), (False, "low"))
        self.assertEqual(self.c.patch(f"/api/sources/{sid}", json={"enabled": "yes"}).status_code, 400)
        self.assertEqual(self.c.patch("/api/sources/nope", json={"enabled": True}).status_code, 404)
        self.assertEqual(self.c.delete("/api/sources/builtin-nvd").status_code, 400)       # built-ins protected
        self.assertEqual(self.c.delete(f"/api/sources/{sid}").status_code, 200)
        self.assertEqual(self.c.delete(f"/api/sources/{sid}").status_code, 404)
        events = [e["event"] for e in self.c.get("/api/audit?n=50").get_json()]
        for ev in ("source_added", "source_edited", "source_disabled", "source_deleted"):
            self.assertIn(ev, events)

    def test_source_test_endpoint(self):
        with mock.patch("source_manager.manager.requests.get", return_value=FakeResp(RSS)):
            r = self.c.post("/api/sources/test", json={"url": "https://feed.test/rss", "type": "rss"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["entry_count"], 2)
        with mock.patch("source_manager.manager.requests.get", return_value=FakeResp(b"<html></html>")):
            r = self.c.post("/api/sources/test", json={"url": "https://feed.test/rss", "type": "rss"})
        self.assertEqual(r.status_code, 422)
        self.assertFalse(r.get_json()["valid"])
        with mock.patch("source_manager.manager.requests.get", side_effect=requests.Timeout()):
            self.assertEqual(self.c.post("/api/sources/test", json={"url": "https://feed.test/rss"}).status_code, 422)
        self.assertEqual(self.c.post("/api/sources/test", json={"url": "javascript:alert(1)"}).status_code, 422)

    def test_analyst_workflow_and_audit(self):
        self._seed_item()
        eid = self.c.get("/api/vulns").get_json()["items"][0]["id"]
        r = self.c.post(f"/api/vulns/{eid}/review", json={"status": "confirmed", "analyst": "Prithvi", "notes": "Confirmed by vendor advisory."})
        self.assertEqual(r.status_code, 201)
        self.assertEqual(self.c.post(f"/api/vulns/{eid}/review", json={"status": "maybe", "analyst": "P"}).status_code, 400)
        self.assertEqual(self.c.post(f"/api/vulns/{eid}/review", json={"status": "resolved", "analyst": ""}).status_code, 400)
        self.assertEqual(self.c.post(f"/api/vulns/{eid}/notes", json={"analyst": "P", "notes": ""}).status_code, 400)
        self.assertEqual(self.c.post(f"/api/vulns/{eid}/notes", json={"analyst": "P", "notes": "follow-up"}).status_code, 201)
        self.assertEqual(self.c.post("/api/vulns/ent-missing/review", json={"status": "resolved", "analyst": "P"}).status_code, 404)
        d = self.c.get(f"/api/vulns/{eid}").get_json()
        self.assertEqual(d["analyst"]["status"], "confirmed")
        self.assertEqual(len(d["analyst_history"]), 2)
        self.assertEqual(self.c.get("/api/vulns?status=confirmed").get_json()["total"], 1)
        self.c.post(f"/api/vulns/{eid}/review", json={"status": "false_positive", "analyst": "P"})
        self.assertEqual(self.c.get("/api/vulns?status=confirmed").get_json()["total"], 0)
        events = [e["event"] for e in self.c.get("/api/audit?n=50").get_json()]
        for ev in ("finding_confirmed", "analyst_note_added", "finding_false_positive"):
            self.assertIn(ev, events)

    def test_optional_token_and_cors(self):
        os.environ["EVVP_API_TOKEN"] = "s3cret"
        try:
            self.assertEqual(self.c.get("/api/health").status_code, 200)                       # reads stay open
            self.assertEqual(self.c.post("/api/sources", json={"name": "a", "url": "https://t.test/f"}).status_code, 401)
            ok = self.c.post("/api/sources", json={"name": "a", "url": "https://t.test/f"},
                             headers={"Authorization": "Bearer s3cret"})
            self.assertEqual(ok.status_code, 201)
        finally:
            os.environ.pop("EVVP_API_TOKEN", None)
        r = self.c.get("/api/health", headers={"Origin": "http://localhost:5173"})
        self.assertEqual(r.headers.get("Access-Control-Allow-Origin"), "http://localhost:5173")
        r = self.c.get("/api/health", headers={"Origin": "http://evil.test"})
        self.assertIsNone(r.headers.get("Access-Control-Allow-Origin"))


if __name__ == "__main__":
    unittest.main()
