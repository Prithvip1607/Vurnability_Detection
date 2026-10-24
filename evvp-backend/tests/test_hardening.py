"""Regression tests for the completion pass: matching accuracy, SSRF guard, NVD linking,
storage mutation, evidence-preserving dedupe, KEV/EPSS enrichment and API behaviour."""
import os
import unittest
from unittest import mock

from tests import helpers  # noqa: F401  (isolates data/log directories first)

from datetime import datetime, timedelta, timezone

from pipeline import epss, kev, nvd_enricher, risk
from pipeline.signal_filter import analyze
from source_manager import manager


def _now():
    return datetime.now(timezone.utc)


class MatchingAccuracy(unittest.TestCase):
    def test_rce_does_not_match_inside_other_words(self):
        r = analyze({"title": "Open source project policy enforcement", "text": "resource force enforce source"})
        self.assertFalse(r.passes)
        self.assertEqual(r.matched_signals, [])
        self.assertIsNone(risk.has_term("a pocket of resources", ("poc", "rce")))

    def test_real_rce_still_matches(self):
        self.assertEqual(risk.has_term("Unauthenticated RCE in Acme", ("rce",)), "rce")

    def test_risk_breakdown_sums_to_score_and_is_explained(self):
        item = {"title": "Acme RCE", "text": "actively exploited, PoC released", "signal_score": 30, "source_trust": "high",
                "nvd_data": [{"cvss_v3": {"score": 9.8}}], "epss": 0.9, "cve_ids": ["CVE-2026-1111"]}
        parts = risk.risk_breakdown(item, 3)
        self.assertEqual(min(100, sum(p["points"] for p in parts)), risk.risk_score(item, 3)[0])
        self.assertTrue({"CVSS", "EPSS", "Source trust", "Cross-source confirmation"} <= {p["factor"] for p in parts})
        self.assertTrue(all(p["detail"] and p["points"] > 0 for p in parts))

    def test_higher_trust_scores_higher_all_else_equal(self):
        base = {"title": "Acme RCE exploited", "text": "x", "signal_score": 20}
        self.assertGreater(risk.risk_score({**base, "source_trust": "authoritative"})[0], risk.risk_score({**base, "source_trust": "low"})[0])

    def test_kev_membership_counts_as_active_exploitation(self):
        self.assertTrue(risk.active_exploitation({"title": "Acme bug", "text": "", "kev": [{"cve_id": "CVE-2026-1"}]}))
        self.assertFalse(risk.active_exploitation({"title": "Acme bug", "text": "patched"}))


class SsrfGuard(unittest.TestCase):
    def setUp(self):
        self._old = os.environ.pop("EVVP_ALLOW_PRIVATE_SOURCES", None)

    def tearDown(self):
        if self._old is not None:
            os.environ["EVVP_ALLOW_PRIVATE_SOURCES"] = self._old

    def test_internal_targets_rejected(self):
        for url in ("http://localhost/feed", "http://127.0.0.1/feed", "http://169.254.169.254/latest/meta-data",
                    "http://10.0.0.5/x", "http://metadata.google.internal/", "ftp://example.com/feed", "file:///etc/passwd",
                    "http://user:pw@example.com/feed"):
            with self.assertRaises(manager.SourceError, msg=url):
                manager.check_url(url, resolve=True)

    def test_public_host_allowed_syntactically(self):
        self.assertEqual(manager.check_url("https://example.com/feed"), "https://example.com/feed")

    def test_hostname_resolving_to_private_ip_rejected(self):
        with mock.patch("source_manager.manager.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("10.1.2.3", 80))]):
            with self.assertRaises(manager.SourceError):
                manager.check_url("http://innocent.example.com/feed", resolve=True)

    def test_redirect_to_internal_address_rejected(self):
        class R:
            status_code, is_redirect, content = 302, True, b""
            headers = {"Location": "http://169.254.169.254/latest"}
        with mock.patch("source_manager.manager.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.216.34", 80))]), \
                mock.patch("source_manager.manager.requests.get", return_value=R()):
            with self.assertRaises(manager.SourceError):
                manager.safe_get("http://public.example.com/feed")


class NvdLinking(unittest.TestCase):
    """An NVD record for a CVE EVVP already tracks must attach to the existing finding (and give it a lead time)."""

    def setUp(self):
        helpers.reset_files()
        import pipeline.processor as proc
        proc._recent_cache, proc._cache_counter = [], 1
        self.proc = proc

    def test_nvd_record_upgrades_existing_early_signal(self):
        from storage import db
        from pipeline.entities import build_entities
        early = {"id": "blog_1", "platform": "blog", "source": "https://blog.example", "title": "Initech Gateway CVE-2026-9001 unauthenticated RCE zero-day exploited",
                 "text": "Unauthenticated remote code execution, PoC published.", "timestamp": (_now() - timedelta(hours=9)).isoformat(),
                 "url": "https://blog.example/a", "metadata": {"source_name": "Researcher Blog"}, "source_trust": "high"}
        with mock.patch.object(self.proc, "enrich", side_effect=lambda i: i if i.get("nvd_data") else {**i, "nvd_data": [], "nvd_status": "not_found"}), \
                mock.patch.object(self.proc, "enrich_epss", side_effect=lambda i: i), mock.patch.object(self.proc, "enrich_kev", side_effect=lambda i: i), \
                mock.patch.object(self.proc, "verify", return_value={"poc_found": False}), mock.patch.object(self.proc, "dispatch"):
            self.assertTrue(self.proc.process(early))
            rec = {"cve_id": "CVE-2026-9001", "description": "Initech RCE", "cvss_v3": {"score": 9.8, "severity": "CRITICAL"},
                   "published": (_now() - timedelta(hours=2)).isoformat(), "references": [], "affected_products": ["initech gateway"], "modified": ""}
            nvd_item = {"id": "nvd_CVE-2026-9001", "platform": "nvd", "source": "nvd_api", "title": "CVE-2026-9001", "text": "Initech RCE",
                        "timestamp": rec["published"], "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-9001", "cve_ids": ["CVE-2026-9001"],
                        "nvd_data": [rec], "nvd_status": "ok", "metadata": {}}
            self.assertFalse(self.proc.process(nvd_item, force=True))      # duplicate → absorbed as evidence, not a new finding
        stored = db.load_recent_raw(0)
        self.assertEqual(len(stored), 1)
        self.assertTrue(stored[0]["nvd_data"], "NVD data must be merged onto the existing finding")
        self.assertEqual(stored[0]["sources"][-1]["platform"], "nvd")
        ent = build_entities(stored)[0]
        self.assertEqual(ent["lead_time"]["status"], "early")
        self.assertTrue(ent["nvd_confirmed"])
        self.assertEqual(ent["severity"], "CRITICAL")

    def test_nvd_collector_forces_tracked_cves_and_isolates_failures(self):
        from ingestion import nvd as nvd_ingest
        with mock.patch.object(nvd_ingest.manager, "gate", return_value={"id": "builtin-nvd"}), \
                mock.patch.object(nvd_ingest.manager, "mark_fetch") as mf, \
                mock.patch.object(nvd_ingest, "_fetch_page", side_effect=Exception("NVD down")):
            nvd_ingest.run_once(force=True)                                 # must not raise
        mf.assert_called_once()
        self.assertFalse(mf.call_args.kwargs["success"])


class EvidenceAndStorage(unittest.TestCase):
    def setUp(self):
        helpers.reset_files()

    def test_update_raw_and_append_source_dedupe(self):
        from storage import db
        db.save_raw({"id": "x1", "platform": "blog", "title": "t", "url": "https://a/1", "collected_at": _now().isoformat()})
        db.append_source("x1", "https://b/2", "github", extra={"source": "GitHub"})
        db.append_source("x1", "https://b/2", "github", extra={"source": "GitHub"})        # same URL again
        db.append_source("x1", "https://a/1", "blog")                                      # the item's own URL
        self.assertEqual(len(db.load_recent_raw(0)[0]["sources"]), 1)
        self.assertTrue(db.update_raw("x1", lambda o: o.update(cve_ids=["CVE-2026-1"]) or True))
        self.assertFalse(db.update_raw("missing", lambda o: True))
        self.assertEqual(db.load_recent_raw(0)[0]["cve_ids"], ["CVE-2026-1"])

    def test_rfc2822_timestamps_are_not_dropped_by_days_filter(self):
        from storage import db
        db.save_raw({"id": "r1", "platform": "blog", "title": "t", "timestamp": "Thu, 03 Sep 2026 10:00:00 +0000"})
        self.assertEqual(db.load_recent_raw(0)[0]["id"], "r1")

    def test_verified_records_persist_in_json_mode(self):
        from storage import db
        db.save_verified({"id": "v1", "raw_id": "x1"})
        self.assertTrue(os.path.exists(os.path.join(os.environ["EVVP_RAW_DATA_DIR"], "verified.jsonl")))


class Enrichers(unittest.TestCase):
    def test_epss_parsed_and_failure_is_silent(self):
        class R:
            def raise_for_status(self): pass
            def json(self): return {"data": [{"cve": "CVE-2026-1", "epss": "0.5", "percentile": "0.9"}]}
        with mock.patch("pipeline.epss.requests.get", return_value=R()):
            out = epss.enrich_epss({"cve_ids": ["CVE-2026-1"]})
        self.assertEqual((out["epss"], out["epss_percentile"]), (0.5, 0.9))
        with mock.patch("pipeline.epss.requests.get", side_effect=ConnectionError("down")):
            self.assertNotIn("epss", epss.enrich_epss({"cve_ids": ["CVE-2026-1"]}))

    def test_kev_flags_listed_cve_only(self):
        kev._cache.update(ts=__import__("time").time(), ids={"CVE-2026-1": {"due": "2026-10-01", "added": "2026-09-01", "ransomware": "Unknown"}})
        self.assertTrue(kev.enrich_kev({"cve_ids": ["CVE-2026-1"]}).get("kev"))
        self.assertNotIn("kev", kev.enrich_kev({"cve_ids": ["CVE-2026-2"]}))

    def test_nvd_status_not_found_keeps_cve(self):
        with mock.patch.object(nvd_enricher, "_fetch_cve", return_value=None), mock.patch.object(nvd_enricher.time, "sleep"):
            out = nvd_enricher.enrich({"title": "CVE-2026-7777 reserved", "text": ""})
        self.assertEqual((out["cve_ids"], out["nvd_status"]), (["CVE-2026-7777"], "not_found"))


class ApiBehaviour(unittest.TestCase):
    def setUp(self):
        helpers.reset_files()
        from api import server
        self.server, self.c = server, server.app.test_client()
        server.invalidate()

    def test_cors_only_for_allowed_origins(self):
        ok = self.c.get("/api/health", headers={"Origin": "http://localhost:5173"})
        bad = self.c.get("/api/health", headers={"Origin": "https://evil.example"})
        self.assertEqual(ok.headers.get("Access-Control-Allow-Origin"), "http://localhost:5173")
        self.assertIsNone(bad.headers.get("Access-Control-Allow-Origin"))

    def test_security_headers_and_ui_served(self):
        r = self.c.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("script-src 'self'", r.headers["Content-Security-Policy"])
        self.assertEqual(self.c.get("/ui/core.js").status_code, 200)
        self.assertNotIn(b"EVVP.start();</script>", r.data)       # no inline script: CSP stays strict

    def test_write_requires_token_when_configured(self):
        os.environ["EVVP_API_TOKEN"] = "s3cret"
        try:
            self.assertEqual(self.c.post("/api/sources", json={"name": "x", "url": "https://x.example/f"}).status_code, 401)
            self.assertEqual(self.c.post("/api/sources", json={"name": "x", "url": "https://x.example/f"},
                                         headers={"Authorization": "Bearer s3cret"}).status_code, 201)
            self.assertEqual(self.c.get("/api/health").status_code, 200)
        finally:
            os.environ.pop("EVVP_API_TOKEN")

    def test_audit_stats_come_from_persisted_log(self):
        from utils.audit import audit, EV_ITEM_COLLECTED
        audit(EV_ITEM_COLLECTED, platform="blog", title="t")
        self.assertGreaterEqual(self.c.get("/api/audit/stats").get_json()["items_collected"], 1)

    def test_oversized_body_rejected(self):
        r = self.c.post("/api/sources", data=b"x" * (1024 * 1024 + 10), content_type="application/json")
        self.assertEqual(r.status_code, 413)


if __name__ == "__main__":
    unittest.main()
