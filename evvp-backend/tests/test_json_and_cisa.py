"""Generic JSON-API/custom source adapter and the CISA KEV collector."""
import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from tests import helpers  # noqa: F401

from ingestion import cisa
from ingestion.feedparse import FeedError
from ingestion.jsonapi import clean_mapping, parse_json_feed
from source_manager import manager

M = {"items_path": "data.items", "id_field": "id", "title_field": "name", "url_field": "link", "date_field": "when", "text_field": "desc"}
DOC = {"data": {"items": [{"id": 7, "name": "Acme RCE", "link": "https://a.example/7", "when": 1790000000, "desc": "text"},
                          {"id": 8, "name": "", "desc": "no title -> skipped"}, "not-a-dict",
                          {"name": "No link or id", "link": "javascript:alert(1)"}]}}


class JsonAdapter(unittest.TestCase):
    def test_maps_fields_skips_bad_rows_and_never_keeps_unsafe_links(self):
        feed = parse_json_feed(json.dumps(DOC).encode(), M, "Src", "https://u")
        self.assertEqual([e["title"] for e in feed["entries"]], ["Acme RCE", "No link or id"])
        self.assertEqual(feed["entries"][0]["id"], "7")
        self.assertTrue(feed["entries"][0]["published"].startswith("2026-"))      # epoch seconds -> ISO
        self.assertEqual(feed["entries"][1]["link"], "")                          # javascript: is not a link

    def test_top_level_list_and_errors(self):
        self.assertEqual(len(parse_json_feed(b'[{"t": "x"}]', {"title_field": "t"})["entries"]), 1)
        for bad, msg in ((b"not json", "not valid JSON"), (json.dumps({"data": 1}).encode(), "does not point to a list")):
            with self.assertRaises(FeedError) as cm:
                parse_json_feed(bad, M)
            self.assertIn(msg, str(cm.exception))

    def test_mapping_validation(self):
        self.assertEqual(clean_mapping({"title_field": "a.b-c_1"}), {"title_field": "a.b-c_1"})
        for bad in (None, {}, {"items_path": "x"}, {"title_field": "a b"}, {"title_field": "a;b"}, {"title_field": "../x"},
                    {"title_field": "t", "evil": "x"}, {"title_field": "x" * 101}, {"title_field": 5}):
            with self.assertRaises(ValueError, msg=str(bad)):
                clean_mapping(bad)

    def test_manager_requires_mapping_and_collects_only_mapped_sources(self):
        helpers.reset_files()
        with self.assertRaises(manager.SourceError):
            manager.add_source({"name": "x", "url": "https://x.example/api", "type": "api"})
        s = manager.add_source({"name": "api", "url": "https://x.example/api", "type": "api", "mapping": M})
        self.assertTrue(s["collectable"])
        self.assertIn(s["id"], [x["id"] for x in manager.enabled_feeds()])
        self.assertNotIn("builtin-nvd", [x["id"] for x in manager.enabled_feeds()])      # built-ins run via their own collectors
        r = manager.update_source(s["id"], {"type": "rss"})                               # switching to RSS drops the mapping
        self.assertIsNone(r["mapping"])
        with self.assertRaises(manager.SourceError):
            manager.update_source(s["id"], {"type": "custom"})                           # ...and switching back needs a new one


class CisaCollector(unittest.TestCase):
    def test_item_shape_and_no_invented_timestamp(self):
        it = cisa._to_item({"cveID": "cve-2026-9", "vendorProject": "Soylent", "product": "Print", "vulnerabilityName": "Soylent Print Bypass",
                            "shortDescription": "Auth bypass.", "dateAdded": "2026-10-01", "dueDate": "2026-10-22", "knownRansomwareCampaignUse": "Known"})
        self.assertEqual((it["platform"], it["cve_ids"], it["timestamp"]), ("cisa", ["CVE-2026-9"], ""))
        self.assertTrue(it["kev"] and "ransomware" in it["text"].lower() and "Exploited in the wild" in it["text"])

    def test_lookback_and_failure_isolation(self):
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        old = (datetime.now(timezone.utc) - timedelta(days=500)).strftime("%Y-%m-%d")
        body = {"vulnerabilities": [{"cveID": "CVE-2026-1", "vulnerabilityName": "New", "dateAdded": today}, {"cveID": "CVE-2019-1", "vulnerabilityName": "Old", "dateAdded": old}, {"dateAdded": today}]}

        class R:
            def raise_for_status(self): pass
            def json(self): return body
        with mock.patch.object(cisa.manager, "gate", return_value={"id": "builtin-cisa-kev"}), mock.patch.object(cisa.manager, "mark_fetch") as mf, \
                mock.patch.object(cisa, "process", return_value=True) as proc, mock.patch.object(cisa.requests, "get", return_value=R()):
            cisa.run_once(force=True)
        self.assertEqual([c.args[0]["cve_ids"][0] for c in proc.call_args_list], ["CVE-2026-1"])
        self.assertTrue(proc.call_args.kwargs["force"])
        self.assertTrue(mf.call_args.kwargs["success"])
        with mock.patch.object(cisa.manager, "gate", return_value={"id": "builtin-cisa-kev"}), mock.patch.object(cisa.manager, "mark_fetch") as mf, \
                mock.patch.object(cisa.requests, "get", side_effect=ConnectionError("down")):
            cisa.run_once(force=True)                                                     # must not raise
        self.assertFalse(mf.call_args.kwargs["success"])


if __name__ == "__main__":
    unittest.main()
