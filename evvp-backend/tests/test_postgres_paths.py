"""Executes every PostgreSQL code path in storage/db.py against a FAKE driver.

This is NOT a substitute for running against a real PostgreSQL server (see README → Verification status).
It does catch the failure classes that need no server: wrong placeholder counts, NameErrors, bad row mapping,
and enrichment fields that are not persisted/round-tripped.
"""
import types
import unittest

from tests import helpers  # noqa: F401

from storage import db


class FakeCursor:
    def __init__(self, store):
        self.s, self._rows = store, []

    def __enter__(self): return self
    def __exit__(self, *a): return False

    def execute(self, sql, params=None):
        params = params or ()
        assert sql.count("%s") == len(params), f"placeholder/param mismatch ({sql.count('%s')} vs {len(params)}): {sql[:60]}"
        q = " ".join(sql.split())
        self.s["sql"].append(q)
        if q.startswith("INSERT INTO intel_raw"):
            cols = ["id", "platform", "source", "title", "body", "author", "source_ts", "url", "metadata", "signal_score", "category",
                    "matched_signals", "negative_signals", "sources", "summary", "collected_at"]
            row = dict(zip(cols, params))
            self.s["raw"].setdefault(row["id"], row)
        elif q.startswith("SELECT * FROM intel_raw WHERE id"):
            r = self.s["raw"].get(params[0])
            self._rows = [dict(r)] if r else []
        elif q.startswith("SELECT * FROM intel_raw"):
            self._rows = [dict(r) for r in self.s["raw"].values()]
        elif q.startswith("UPDATE intel_raw SET"):
            r = self.s["raw"][params[3]]
            r["metadata"], r["sources"], r["summary"] = params[0], params[1], params[2]
        elif q.startswith("INSERT INTO intel_verified") or q.startswith("INSERT INTO intel_verification_results"):
            self.s["verified"].append(params)
        elif q.startswith("SELECT * FROM intel_verification_results"):
            self._rows = []
        elif q.startswith("CREATE"):
            pass
        else:
            raise AssertionError("unexpected SQL: " + q[:80])

    def fetchone(self): return self._rows[0] if self._rows else None
    def fetchall(self): return self._rows


class FakeConn:
    def __init__(self, store): self.s = store
    def cursor(self, **kw): return FakeCursor(self.s)
    def commit(self): pass
    def rollback(self): pass


class FakePool:
    store = {"raw": {}, "verified": [], "sql": []}

    def __init__(self, *a): pass
    def getconn(self): return FakeConn(self.store)
    def putconn(self, c): pass


class PostgresCodePaths(unittest.TestCase):
    def setUp(self):
        FakePool.store = {"raw": {}, "verified": [], "sql": []}
        self._saved = {k: getattr(db, k, None) for k in ("psycopg2", "pg_pool", "PSYCOPG2_AVAILABLE", "DB_URL", "_pool")}
        db.psycopg2 = types.SimpleNamespace(extras=types.SimpleNamespace(Json=lambda o, dumps=None: o, RealDictCursor=object))
        db.pg_pool = types.SimpleNamespace(ThreadedConnectionPool=FakePool)
        db.PSYCOPG2_AVAILABLE, db.DB_URL, db._pool = True, "postgresql://fake", None
        self.errors = []                                           # db.py swallows PG errors and falls back to JSON: surface them
        self._orig_error = db.logger.error
        db.logger.error = lambda *a, **k: self.errors.append(a)

    def tearDown(self):
        db.logger.error = self._orig_error
        for k, v in self._saved.items():
            setattr(db, k, v)
        self.assertEqual(self.errors, [], "a PostgreSQL code path raised and silently fell back to JSON")

    def test_round_trip_keeps_enrichment_fields(self):
        item = {"id": "p1", "platform": "blog", "source": "s", "title": "T", "text": "body", "author": "a", "timestamp": "Thu, 03 Sep 2026 10:00:00 +0000",
                "url": "https://x/1", "metadata": {"source_name": "Blog"}, "cve_ids": ["CVE-2026-1111"], "nvd_data": [{"cve_id": "CVE-2026-1111", "cvss_v3": {"score": 9.8}}],
                "nvd_status": "ok", "epss": 0.5, "epss_percentile": 0.9, "kev": [{"cve_id": "CVE-2026-1111"}], "intelligence": {"risk_score": 80},
                "source_trust": "high", "source_trust_weight": 80, "signal_score": 20, "category": "c", "matched_signals": ["rce"], "sources": [{"url": "https://x/1", "platform": "blog"}],
                "summary": "s", "collected_at": "2026-10-06T10:00:00+00:00"}
        self.assertTrue(db._use_postgres())
        db.save_raw(item)
        db.save_raw(item)                                          # idempotent
        back = db.load_recent_raw(0)[0]
        for k in ("cve_ids", "nvd_data", "nvd_status", "epss", "epss_percentile", "kev", "intelligence", "source_trust", "source_trust_weight"):
            self.assertEqual(back.get(k), item[k], k)
        self.assertEqual((back["text"], back["title"], back["timestamp"]), ("body", "T", item["timestamp"]))
        self.assertEqual(back["metadata"], {"source_name": "Blog"}, "internal _x block must not leak into metadata")
        self.assertEqual(len([s for s in FakePool.store["sql"] if s.startswith("INSERT INTO intel_raw")]), 2)

    def test_update_and_append_source(self):
        db.save_raw({"id": "p2", "platform": "blog", "title": "T", "text": "", "url": "https://x/2", "collected_at": "2026-10-06T10:00:00+00:00"})
        self.assertTrue(db.update_raw("p2", lambda o: o.update(cve_ids=["CVE-2026-2"], nvd_status="not_found") or True))
        db.append_source("p2", "https://y/3", "github", extra={"source": "GitHub"})
        db.append_source("p2", "https://y/3", "github", extra={"source": "GitHub"})
        back = db.load_recent_raw(0)[0]
        self.assertEqual((back["cve_ids"], back["nvd_status"]), (["CVE-2026-2"], "not_found"))
        self.assertEqual([s["url"] for s in back["sources"]], ["https://y/3"])
        self.assertFalse(db.update_raw("missing", lambda o: True))

    def test_verified_and_verification_records(self):
        db.save_verified({"id": "v1", "raw_id": "p1", "cve_ids": ["CVE-2026-1"], "metadata": {"a": 1}})
        db.save_verification({"id": "r1", "raw_id": "p1", "verification_status": "verified", "credibility_score": 70})
        self.assertEqual(len(FakePool.store["verified"]), 2)
        self.assertEqual(db.load_verifications(0), [])

    def test_sql_has_no_interpolated_values(self):
        db.save_raw({"id": "p3", "platform": "blog", "title": "x'; DROP TABLE intel_raw;--", "text": "", "collected_at": "2026-10-06T10:00:00+00:00"})
        db.load_recent_raw(7)
        for q in FakePool.store["sql"]:
            self.assertNotIn("DROP TABLE", q)


if __name__ == "__main__":
    unittest.main()
