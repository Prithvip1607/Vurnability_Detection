"""Real-world response shapes and service rules (offline): NVD CVSS selection, NVD throttling, feedparser branch, NVD status exposure."""
import time
import types
import unittest
from unittest import mock

from tests import helpers  # noqa: F401

from ingestion import feedparse
from ingestion.feedparse import FeedError
from pipeline import nvd_enricher


def nvd(metrics, cve="CVE-2026-0001"):
    return {"id": cve, "published": "2026-01-02T10:15:09.143", "lastModified": "2026-01-05T09:00:00.000", "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": "desc"}], "metrics": metrics,
            "references": [{"url": "https://x/1", "source": "s", "tags": ["Patch"]}],
            "configurations": [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"}]}]}]}


def m31(score, sev, typ):
    return {"source": "x", "type": typ, "cvssData": {"version": "3.1", "vectorString": f"CVSS:3.1/AV:N/{score}", "baseScore": score, "baseSeverity": sev}}


class NvdShapes(unittest.TestCase):
    def test_nvds_primary_score_beats_a_cna_score_listed_first(self):
        r = nvd_enricher.parse_nvd_cve(nvd({"cvssMetricV31": [m31(7.5, "HIGH", "Secondary"), m31(10.0, "CRITICAL", "Primary")]}))
        self.assertEqual((r["cvss_v3"]["score"], r["cvss_v3"]["severity"]), (10.0, "CRITICAL"))
        self.assertEqual(r["affected_products"], ["apache log4j"])

    def test_v40_only_cves_still_get_a_score(self):
        v4 = {"source": "x", "type": "Primary", "cvssData": {"version": "4.0", "vectorString": "CVSS:4.0/AV:N", "baseScore": 9.3, "baseSeverity": "CRITICAL"}}
        r = nvd_enricher.parse_nvd_cve(nvd({"cvssMetricV40": [v4]}))
        self.assertEqual((r["cvss_v3"]["score"], r["cvss_v3"]["version"]), (9.3, "4.0"))

    def test_v31_preferred_over_v40_and_v2_is_the_last_resort(self):
        v4 = {"type": "Primary", "cvssData": {"version": "4.0", "baseScore": 5.0, "baseSeverity": "MEDIUM"}}
        self.assertEqual(nvd_enricher.parse_nvd_cve(nvd({"cvssMetricV31": [m31(8.8, "HIGH", "Primary")], "cvssMetricV40": [v4]}))["cvss_v3"]["score"], 8.8)
        r = nvd_enricher.parse_nvd_cve(nvd({"cvssMetricV2": [{"type": "Primary", "baseSeverity": "HIGH", "cvssData": {"baseScore": 7.2}}]}))
        self.assertEqual((r["cvss_v3"], r["cvss_v2"]["score"]), ({}, 7.2))

    def test_record_without_any_metrics_has_no_score(self):
        r = nvd_enricher.parse_nvd_cve(nvd({}))
        self.assertEqual((r["cvss_v3"], r["cvss_v2"]), ({}, {}))

    def test_throttle_spaces_requests_to_respect_the_public_rate_limit(self):
        sleeps = []
        with mock.patch.object(nvd_enricher, "NVD_MIN_INTERVAL", 6.5), mock.patch.object(nvd_enricher, "_last_request", time.monotonic()), \
                mock.patch.object(nvd_enricher.time, "sleep", side_effect=sleeps.append):
            nvd_enricher.throttle()
        self.assertTrue(sleeps and 5.5 <= sleeps[0] <= 6.5, sleeps)
        with mock.patch.object(nvd_enricher, "NVD_MIN_INTERVAL", 0), mock.patch.object(nvd_enricher.time, "sleep") as sl:
            nvd_enricher.throttle()
        sl.assert_not_called()

    def test_lookup_throttles_network_requests_but_not_cache_hits(self):
        class R:
            status_code = 200
            def raise_for_status(self): pass
            def json(self): return {"vulnerabilities": [{"cve": nvd({"cvssMetricV31": [m31(9.8, "CRITICAL", "Primary")]}, "CVE-2026-4321")}]}
        nvd_enricher._CACHE.clear()
        with mock.patch.object(nvd_enricher, "throttle") as th, mock.patch.object(nvd_enricher.requests, "get", return_value=R()) as g:
            nvd_enricher._fetch_cve("CVE-2026-4321")
            nvd_enricher._fetch_cve("CVE-2026-4321")
        self.assertEqual((th.call_count, g.call_count), (1, 1))
        self.assertIn("User-Agent", g.call_args.kwargs["headers"])


class FD(dict):                                   # feedparser's FeedParserDict: dict with attribute access
    __getattr__ = dict.get


class FeedparserBranch(unittest.TestCase):
    """Executes ingestion.feedparse._feedparser_parse with a stub that mimics feedparser's documented result objects."""

    def run_with(self, result):
        stub = types.SimpleNamespace(parse=lambda content: result, CharacterEncodingOverride=type("CharacterEncodingOverride", (Exception,), {}))
        with mock.patch.object(feedparse, "_fp", stub):
            return feedparse.parse_feed(b"<rss/>"), stub

    def test_entries_are_mapped(self):
        res = FD(bozo=0, feed=FD(title="T", link="https://t"), entries=[
            FD(id="1", title="A", link="https://a", published="Thu, 01 Jan 2026 00:00:00 GMT", author="x", content=[FD(value="body")], tags=[FD(term="cve")]),
            FD(link="https://b", title="B", summary="sum", updated="2026-01-02T00:00:00Z")])
        out, _ = self.run_with(res)
        self.assertEqual([e["title"] for e in out["entries"]], ["A", "B"])
        self.assertEqual((out["entries"][0]["content"], out["entries"][0]["tags"], out["entries"][1]["id"], out["entries"][1]["published"]),
                         ("body", ["cve"], "https://b", "2026-01-02T00:00:00Z"))

    def test_broken_xml_without_entries_is_invalid_even_if_a_title_was_salvaged(self):
        with self.assertRaises(FeedError):
            self.run_with(FD(bozo=1, bozo_exception=SyntaxError("mismatched tag"), feed=FD(title="broken"), entries=[]))

    def test_recoverable_xml_with_entries_is_accepted_and_valid_empty_feed_is_ok(self):
        out, _ = self.run_with(FD(bozo=1, bozo_exception=SyntaxError("x"), feed=FD(title="T"), entries=[FD(title="A", link="https://a")]))
        self.assertEqual(len(out["entries"]), 1)
        out, _ = self.run_with(FD(bozo=0, feed=FD(title="Empty"), entries=[]))
        self.assertEqual(out["entries"], [])

    def test_benign_encoding_warning_is_not_an_error(self):
        stub = types.SimpleNamespace(CharacterEncodingOverride=type("CharacterEncodingOverride", (Exception,), {}))
        res = FD(bozo=1, bozo_exception=stub.CharacterEncodingOverride("x"), feed=FD(title="T"), entries=[])
        stub.parse = lambda c: res
        with mock.patch.object(feedparse, "_fp", stub):
            self.assertEqual(feedparse.parse_feed(b"<rss/>")["entries"], [])


class NvdStatusIsHonest(unittest.TestCase):
    def test_not_found_and_unavailable_are_exposed_but_never_when_nvd_confirms(self):
        from pipeline.entities import build_entities
        base = {"platform": "blog", "title": "Initech CVE-2026-777 RCE", "text": "x", "cve_ids": ["CVE-2026-777"], "collected_at": "2026-10-06T10:00:00+00:00",
                "timestamp": "2026-10-06T09:00:00+00:00", "url": "https://x/1", "source_trust": "high", "id": "n1"}
        self.assertEqual(build_entities([{**base, "nvd_status": "not_found", "nvd_data": []}])[0]["nvd_status"], "not_found")
        self.assertEqual(build_entities([{**base, "nvd_status": "unavailable", "nvd_data": []}])[0]["nvd_status"], "unavailable")
        ok = build_entities([{**base, "nvd_status": "ok", "nvd_data": [{"cve_id": "CVE-2026-777", "cvss_v3": {"score": 9.0}}]}])[0]
        self.assertIsNone(ok["nvd_status"])
        self.assertTrue(ok["nvd_confirmed"])


if __name__ == "__main__":
    unittest.main()
