"""Regression tests for correlation bugs found while running EVVP on its own shipped data.

1. Novelty rule 5 merged *unrelated* stories that merely shared generic terms ("rce",
   "unauthenticated", "actively exploited"), silently discarding a distinct finding and
   fabricating cross-source confirmation.
2. The same publisher counted twice because it was labelled "The Hacker News" on one
   evidence row and "thehackernews.com" on another.
3. A genuine duplicate kept only its URL; its name, timestamp and trust were lost so the
   timeline and lead time could not use it.
"""
import json
import os
import unittest
from datetime import datetime, timedelta, timezone

from tests import helpers
from pipeline import novelty
from pipeline.entities import build_entities, source_key

T0 = datetime(2026, 9, 3, 10, 0, tzinfo=timezone.utc)


def _it(iid, title, text="", platform="blog", **kw):
    it = {"id": iid, "platform": platform, "title": title, "text": text, "url": f"https://{iid}.test/post",
          "timestamp": T0.isoformat(), "collected_at": (T0 + timedelta(minutes=5)).isoformat(),
          "signal_score": 20, "cve_ids": [], "nvd_data": [], "source_trust": "medium",
          "source_trust_weight": 55, "metadata": {}}
    it.update(kw)
    return it


class NoveltyFalseMerge(unittest.TestCase):
    GENERIC = "unauthenticated RCE exploited, PoC released, actively exploited zero-day"

    def test_unrelated_stories_sharing_generic_terms_are_both_novel(self):
        geonetwork = _it("a", "GeoNetwork Fixes Unauthenticated RCE Chain Affecting Government Portals", self.GENERIC)
        langflow = _it("b", "Critical Langflow Flaw Lets Anyone Hijack AI Workflows", self.GENERIC)
        res = novelty.check(langflow, existing=[geonetwork])
        self.assertTrue(res.is_novel, f"unrelated story was merged: {res.reason}")

    def test_same_story_from_another_outlet_is_still_a_duplicate(self):
        a = _it("a", "SonicWall SMA1000 zero-day under attack", self.GENERIC)
        b = _it("b", "SonicWall warns SMA1000 appliances hit by zero-day", self.GENERIC)
        res = novelty.check(b, existing=[a])
        self.assertFalse(res.is_novel)
        self.assertEqual(res.duplicate_id, "a")


class SourceIdentity(unittest.TestCase):
    def test_source_key_normalises_name_and_domain(self):
        for a, b in [("The Hacker News", "thehackernews.com"), ("BleepingComputer", "www.bleepingcomputer.com"),
                     ("GitHub", "github.com"), ("Project Zero", "projectzero.google"),
                     ("SecurityWeek", "securityweek.com")]:
            self.assertEqual(source_key(a), source_key(b), (a, b))
        self.assertNotEqual(source_key("Dark Reading"), source_key("SecurityWeek"))

    def test_same_publisher_counts_once(self):
        item = _it("a", "Switchvox flaw exploited", platform="blog", metadata={"source_name": "BleepingComputer"},
                   url="https://www.bleepingcomputer.com/news/a",
                   sources=[{"url": "https://www.bleepingcomputer.com/news/a", "platform": "blog"},
                            {"url": "https://www.bleepingcomputer.com/news/b", "platform": "blog"}])
        ent = build_entities([item])[0]
        self.assertEqual(ent["cross_source_count"], 1)
        self.assertEqual(len(ent["sources"]), 1)

    def test_two_real_publishers_count_twice(self):
        item = _it("a", "Switchvox flaw exploited", metadata={"source_name": "BleepingComputer"},
                   url="https://www.bleepingcomputer.com/news/a",
                   sources=[{"url": "https://www.bleepingcomputer.com/news/a", "platform": "blog"},
                            {"url": "https://www.securityweek.com/x", "platform": "blog"}])
        self.assertEqual(build_entities([item])[0]["cross_source_count"], 2)


class DuplicateKeepsEvidence(unittest.TestCase):
    def test_merged_duplicate_contributes_name_time_and_trust(self):
        later = T0 + timedelta(hours=3)
        item = _it("a", "Acme Gateway RCE zero-day", metadata={"source_name": "Researcher Blog"},
                   sources=[{"url": "https://a.test/post", "platform": "blog"},
                            {"url": "https://news.test/acme", "platform": "blog", "source": "News Site",
                             "observed_at": later.isoformat(), "trust": "high", "evidence_type": "news_report",
                             "title": "Acme Gateway hit by RCE zero-day"}])
        ent = build_entities([item])[0]
        news = [e for e in ent["evidence"] if e["url"] == "https://news.test/acme"][0]
        self.assertEqual(news["source"], "News Site")
        self.assertEqual(news["trust"], "high")
        self.assertEqual(news["observed_at"], later.isoformat())
        self.assertEqual(ent["timeline"]["undated_mentions"], 0)
        self.assertIn("News Site", [ev["source"] for ev in ent["timeline"]["events"]])

    def test_legacy_sources_without_metadata_still_work(self):
        item = _it("a", "Acme Gateway RCE zero-day",
                   sources=[{"url": "https://a.test/post", "platform": "blog"},
                            {"url": "https://old.test/x", "platform": "blog"}])
        ent = build_entities([item])[0]
        self.assertEqual(ent["cross_source_count"], 2)
        self.assertEqual(ent["timeline"]["undated_mentions"], 1)      # honest: no timestamp invented


class StorageAppend(unittest.TestCase):
    def test_append_source_stores_metadata_and_dedupes_by_url(self):
        helpers.reset_files()
        from storage import db
        db.save_raw({"id": "x1", "platform": "blog", "title": "t", "url": "https://x.test/1",
                     "sources": [{"url": "https://x.test/1", "platform": "blog"}]})
        extra = {"source": "News Site", "observed_at": "2026-09-03T12:00:00+00:00", "trust": "high"}
        db.append_source("x1", "https://n.test/1", "blog", extra=extra)
        db.append_source("x1", "https://n.test/1", "blog", extra=extra)       # same URL again
        stored = [i for i in db.load_recent_raw(days=0) if i["id"] == "x1"][0]
        urls = [s["url"] for s in stored["sources"]]
        self.assertEqual(urls.count("https://n.test/1"), 1)
        row = [s for s in stored["sources"] if s["url"] == "https://n.test/1"][0]
        self.assertEqual(row["source"], "News Site")
        self.assertEqual(row["trust"], "high")


if __name__ == "__main__":
    unittest.main()


class RoundupArticles(unittest.TestCase):
    """A roundup naming many CVEs is context, not a vulnerability."""

    def _roundup(self):
        nvd = [{"cve_id": f"CVE-2026-100{i}", "published": T0.isoformat(), "description": f"Flaw number {i}",
                "cvss_v3": {"score": 9.8, "severity": "CRITICAL", "vector": "CVSS:3.1/AV:N"}} for i in range(5)]
        return _it("r", "July 2026 CVE Landscape", "Roundup of " + " ".join(n["cve_id"] for n in nvd),
                   cve_ids=[n["cve_id"] for n in nvd], nvd_data=nvd)

    def test_roundup_does_not_borrow_cvss_or_description_from_a_mentioned_cve(self):
        ents = build_entities([self._roundup()])
        roundup = [e for e in ents if e["roundup"]][0]
        self.assertIsNone(roundup["cvss"])
        self.assertNotIn("Flaw number", roundup["description"])
        self.assertIsNone(roundup["lead_time"]["seconds"])

    def test_cve_records_still_built_from_roundup_nvd_data(self):
        item = self._roundup()
        ents = build_entities([item])
        recs = build_cve_records_for(ents, [item])
        self.assertEqual(len(recs), 5)
        self.assertTrue(all(r["cvss"] == 9.8 for r in recs))


def build_cve_records_for(ents, items):
    from pipeline.entities import build_cve_records
    return build_cve_records(ents, items)
