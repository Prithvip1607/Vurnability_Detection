"""Signal detection, CVE extraction, dedupe boundaries, add-source SSRF, analyst-decision semantics."""
import unittest

from tests import helpers  # noqa: F401

from pipeline import novelty, risk
from pipeline.nvd_enricher import item_cve_ids
from pipeline.signal_filter import analyze
from source_manager import manager

SIGNALS = {
    "Unauthenticated RCE in Acme Gateway": "RCE",
    "Remote Code Execution flaw in Acme Router": "Remote Code Execution",
    "Acme VPN zero-day exploited": "Zero-Day",
    "Acme firewall 0-day under attack": "0-Day",
    "Public exploit released for Acme CMS": "Exploit",
    "PoC published for Acme CMS vulnerability": "PoC",
    "Acme server actively exploited in the wild": "Active Exploitation",
    "Acme kernel privilege escalation vulnerability": "Privilege Escalation",
    "Authentication bypass in Acme portal": "Authentication Bypass",
    "SQL injection vulnerability in Acme shop": "SQL Injection",
    "Buffer overflow vulnerability in Acme daemon": "Buffer Overflow",
    "Unauthenticated attacker can take over Acme console": "Unauthenticated",
    "Command injection vulnerability in Acme camera": "Command Injection",
}
NOT_SIGNALS = ["Open source policy enforcement", "Force majeure notice for the resource group", "Company picnic photos",
               "A pocket guide to resource planning", "Weekly newsletter: sources of inspiration"]


class SignalDetection(unittest.TestCase):
    def test_each_required_signal_is_detected(self):
        for title, label in SIGNALS.items():
            r = analyze({"title": title, "text": ""})
            self.assertTrue(r.matched_signals, f"{label}: nothing matched for {title!r}")

    def test_lookalike_words_do_not_match(self):
        for title in NOT_SIGNALS:
            r = analyze({"title": title, "text": title})
            self.assertEqual(r.matched_signals, [], title)
            self.assertFalse(r.passes, title)

    def test_exploit_word_is_not_active_exploitation(self):
        self.assertFalse(risk.active_exploitation({"title": "PoC exploit released for Acme", "text": "a working exploit is available"}))
        self.assertTrue(risk.poc_available({"title": "PoC exploit released for Acme", "text": ""}))
        for t in ("Acme exploited in the wild", "Acme zero-day actively exploited", "Acme under active attack"):
            self.assertTrue(risk.active_exploitation({"title": t, "text": ""}), t)

    def test_attack_mapping_only_with_evidence(self):
        self.assertEqual({t["id"] for t in risk.attack_techniques({"title": "Remote code execution and privilege escalation", "text": ""})}, {"T1190", "T1068"})
        self.assertEqual(risk.attack_techniques({"title": "Quarterly newsletter", "text": "nothing here"}), [])
        self.assertEqual(risk.attack_techniques({"title": "Resource force source", "text": ""}), [])


class CveExtraction(unittest.TestCase):
    def test_formats_and_normalisation(self):
        got = item_cve_ids({"title": "cve-2026-12345 and CVE-2025-0001", "text": "see CVE-2024-99999, cve-2026-12345 again; CVE-26-1 and CVE-2026-12 are invalid"})
        self.assertEqual(got, ["CVE-2024-99999", "CVE-2025-0001", "CVE-2026-12345"])

    def test_long_ids_and_no_cve(self):
        self.assertEqual(item_cve_ids({"title": "CVE-2026-1234567", "text": ""}), ["CVE-2026-1234567"])
        self.assertEqual(item_cve_ids({"title": "No identifier", "text": "nothing"}), [])


class DedupeBoundaries(unittest.TestCase):
    G = "unauthenticated RCE exploited in the wild"

    def test_products_sharing_only_generic_words_stay_separate(self):
        a = {"id": "a", "title": "Initech Gateway unauthenticated RCE zero-day exploited in the wild", "text": self.G}
        for t in ("Wayne Gateway unauthenticated RCE exploited in the wild", "Hooli Gateway remote code execution exploited in the wild",
                  "Critical flaw in Acme Router actively exploited in the wild"):
            self.assertTrue(novelty.check({"id": "b", "title": t, "text": self.G}, existing=[a]).is_novel, t)

    def test_same_story_different_wording_merges(self):
        a = {"id": "a", "title": "SonicWall SMA1000 zero-day under attack", "text": self.G}
        b = {"id": "b", "title": "SonicWall warns SMA1000 appliances hit by zero-day", "text": self.G}
        self.assertFalse(novelty.check(b, existing=[a]).is_novel)

    def test_cve_overlap_merges_and_distinct_cves_do_not(self):
        a = {"id": "a", "title": "Foo bar", "text": "CVE-2026-1000", "cve_ids": ["CVE-2026-1000"]}
        self.assertFalse(novelty.check({"id": "b", "title": "Something else", "text": "", "cve_ids": ["CVE-2026-1000"]}, existing=[a]).is_novel)
        self.assertTrue(novelty.check({"id": "c", "title": "Something else", "text": "", "cve_ids": ["CVE-2026-2000"]}, existing=[a]).is_novel)


class AddSourceSsrf(unittest.TestCase):
    def setUp(self):
        import os
        self._old = os.environ.pop("EVVP_ALLOW_PRIVATE_SOURCES", None)

    def tearDown(self):
        import os
        if self._old is not None:
            os.environ["EVVP_ALLOW_PRIVATE_SOURCES"] = self._old

    def test_ip_literals_rejected_when_adding(self):
        for url in ("http://127.0.0.1:8000/api/health", "http://10.1.1.1/f", "http://192.168.0.5/f", "http://169.254.169.254/x",
                    "http://[::1]/f", "http://0.0.0.0/f", "http://localhost/f"):
            with self.assertRaises(manager.SourceError, msg=url):
                manager.add_source({"name": "x", "url": url})


class ProductList(unittest.TestCase):
    def test_cve_ids_are_not_listed_as_affected_products(self):
        from pipeline.entities import build_entities
        item = {"id": "i1", "platform": "blog", "title": "Initech Gateway CVE-2026-55501 RCE", "text": "x", "cve_ids": ["CVE-2026-55501"],
                "collected_at": "2026-10-06T10:00:00+00:00", "timestamp": "2026-10-06T09:00:00+00:00", "url": "https://x/1", "source_trust": "high"}
        ent = build_entities([item], verifications=[{"raw_id": "i1", "affected_products": ["CVE-2026-55501", "initech gateway"]}])[0]
        self.assertEqual(ent["affected_products"], ["initech gateway"])


class AnalystSemantics(unittest.TestCase):
    def test_note_by_another_analyst_does_not_replace_the_decision(self):
        helpers.reset_files()
        from storage import analyst
        ent = {"id": "ent-1", "item_ids": ["i1"], "cve_ids": [], "title": "T", "analyst": {"status": "potential"}}
        analyst.record(ent, "confirmed", "alice", "Confirmed by vendor")
        analyst.record({**ent, "analyst": {"status": "confirmed"}}, None, "bob", "patched on staging", kind="note")
        cur = analyst.latest_by_entity()["ent-1"]
        self.assertEqual((cur["status"], cur["analyst"], cur["notes"]), ("confirmed", "alice", "Confirmed by vendor"))
        self.assertEqual(cur["last_note"]["analyst"], "bob")


if __name__ == "__main__":
    unittest.main()
