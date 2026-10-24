import unittest
from datetime import datetime, timedelta, timezone

from tests import helpers  # noqa: F401
from pipeline.entities import build_entities, build_cve_records, compute_timing
from pipeline.risk import build_intelligence
from utils.timeutil import parse_ts, format_duration

T0 = datetime(2026, 9, 3, 10, 0, tzinfo=timezone.utc)


def _item(iid, platform, title, ts, collected, text="", cves=None, nvd=None, name=None, trust="medium", **kw):
    it = {"id": iid, "platform": platform, "title": title, "text": text, "url": f"https://x.test/{iid}",
          "timestamp": ts.isoformat() if ts else "", "collected_at": collected.isoformat(),
          "signal_score": 20, "cve_ids": cves or [], "nvd_data": nvd or [],
          "source_trust": trust, "source_trust_weight": 55, "metadata": {"source_name": name} if name else {}}
    it.update(kw)
    return it


class Correlation(unittest.TestCase):
    def setUp(self):
        early = _item("b1", "blog", "Acme Gateway unauthenticated RCE zero-day exploited",
                      T0, T0 + timedelta(minutes=5), "No patch yet.", name="Researcher Blog")
        poc = _item("g1", "github", "acme-gateway-unauthenticated-rce-poc", T0 + timedelta(hours=1),
                    T0 + timedelta(hours=1), "PoC exploit for Acme Gateway", name=None)
        news = _item("b2", "blog", "Acme Gateway unauthenticated RCE CVE-2026-9999 patched", T0 + timedelta(hours=7),
                     T0 + timedelta(hours=7, minutes=2), "CVE-2026-9999 fixed", cves=["CVE-2026-9999"], name="News Site")
        nvd = _item("n1", "nvd", "CVE-2026-9999", T0 + timedelta(hours=7, minutes=40), T0 + timedelta(hours=8),
                    "Acme Gateway RCE", cves=["CVE-2026-9999"], trust="authoritative",
                    nvd=[{"cve_id": "CVE-2026-9999", "published": (T0 + timedelta(hours=7, minutes=40)).isoformat(),
                          "cvss_v3": {"score": 9.8, "severity": "CRITICAL", "vector": "CVSS:3.1/AV:N"},
                          "description": "RCE in Acme Gateway", "references": ["https://acme.test/adv"]}])
        self.items = [early, poc, news, nvd]

    def test_early_signal_links_to_cve_entity(self):
        ents = build_entities(self.items)
        self.assertEqual(len(ents), 1, [e["title"] for e in ents])
        e = ents[0]
        self.assertEqual(e["cve_ids"], ["CVE-2026-9999"])
        self.assertEqual(e["cross_source_count"], 4)          # researcher blog, GitHub, news, NVD
        self.assertEqual(e["severity"], "CRITICAL")
        self.assertFalse(e["zero_day_candidate"])             # a CVE now exists

    def test_lead_time_uses_real_timestamps(self):
        e = build_entities(self.items)[0]
        self.assertEqual(e["lead_time"]["status"], "early")
        self.assertEqual(e["lead_time"]["basis"], "evvp_detection")
        # CVE published 07:40 after T0 vs EVVP first collected at 00:05 -> 7h 35m
        self.assertEqual(e["lead_time"]["human"], "7h 35m")
        self.assertEqual(e["first_collected"], (T0 + timedelta(minutes=5)).isoformat())
        self.assertEqual(e["first_public_signal"], T0.isoformat())

    def test_timeline_order(self):
        events = build_entities(self.items)[0]["timeline"]["events"]
        types = [ev["type"] for ev in events]
        self.assertTrue(events[0].get("first_observed"))
        self.assertEqual(events[0]["source"], "Researcher Blog")      # earliest signal first
        self.assertEqual([ev["ts"] for ev in events], sorted(ev["ts"] for ev in events))
        self.assertIn("poc_detected", types)
        self.assertIn("nvd_record", types)
        self.assertLess(types.index("poc_detected"), types.index("nvd_record"))

    def test_without_cve_it_is_a_zero_day_candidate_not_a_certainty(self):
        e = build_entities(self.items[:2])[0]
        self.assertTrue(e["zero_day_candidate"])
        self.assertTrue(e["zero_day_evidence"])
        self.assertEqual(e["lead_time"]["status"], "no_cve")
        self.assertIsNone(e["lead_time"]["seconds"])

    def test_signal_after_cve_is_reported_honestly(self):
        late = _item("b9", "blog", "Zeta Router bug CVE-2026-1111", T0 + timedelta(hours=5), T0 + timedelta(hours=5),
                     cves=["CVE-2026-1111"])
        nvd = _item("n9", "nvd", "CVE-2026-1111", T0, T0, cves=["CVE-2026-1111"],
                    nvd=[{"cve_id": "CVE-2026-1111", "published": T0.isoformat()}])
        e = build_entities([late, nvd])[0]
        self.assertEqual(e["lead_time"]["status"], "after_cve")

    def test_missing_timestamps_are_not_fabricated(self):
        it = _item("x", "blog", "Solo item CVE-2026-2222", None, T0, cves=["CVE-2026-2222"])
        it["collected_at"] = ""
        e = build_entities([it])[0]
        self.assertIsNone(e["first_seen"])
        self.assertEqual(e["lead_time"]["status"], "no_cve")

    def test_roundup_is_context_not_a_bridge(self):
        cves = [f"CVE-2026-{3000 + i}" for i in range(6)]
        roundup = _item("r1", "blog", "July CVE landscape", T0, T0, " ".join(cves), cves=cves, name="Recorded Future")
        a = _item("n3000", "nvd", cves[0], T0, T0, cves=[cves[0]], trust="authoritative")
        b = _item("n3001", "nvd", cves[1], T0, T0, cves=[cves[1]], trust="authoritative")
        ents = build_entities([roundup, a, b])
        by_cve = {tuple(e["cve_ids"]): e for e in ents if not e["roundup"]}
        self.assertIn((cves[0],), by_cve)
        self.assertIn((cves[1],), by_cve)                    # not merged into one mega-entity
        self.assertIn("Recorded Future", by_cve[(cves[0],)]["sources"])  # but counted as a mention
        self.assertEqual(len([e for e in ents if e["roundup"]]), 1)
        recs = build_cve_records(ents, [roundup, a, b])
        self.assertEqual(len({r["cve_id"] for r in recs}), len(recs))   # one record per CVE

    def test_analyst_status_is_attached(self):
        e0 = build_entities(self.items)[0]
        dec = {e0["id"]: {"entity_id": e0["id"], "status": "confirmed", "ts": "2026-09-04T00:00:00+00:00", "item_ids": e0["item_ids"]}}
        e1 = build_entities(self.items, decisions=dec)[0]
        self.assertEqual(e1["analyst"]["status"], "confirmed")


class TimeUtil(unittest.TestCase):
    def test_parse_formats(self):
        self.assertEqual(parse_ts("Thu, 03 Sep 2026 11:56:59 +0530"), datetime(2026, 9, 3, 6, 26, 59, tzinfo=timezone.utc))
        self.assertEqual(parse_ts("2026-09-03T06:56:39Z"), datetime(2026, 9, 3, 6, 56, 39, tzinfo=timezone.utc))
        self.assertIsNone(parse_ts("garbage"))
        self.assertIsNone(parse_ts(""))

    def test_duration(self):
        self.assertEqual(format_duration(7 * 3600 + 25 * 60), "7h 25m")
        self.assertEqual(format_duration(90000), "1d 1h 0m")


if __name__ == "__main__":
    unittest.main()
