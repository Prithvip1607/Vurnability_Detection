"""PostgreSQL configured => failures are explicit. There must be NO silent fallback to JSON files."""
import os
import subprocess
import sys
import types
import unittest
from unittest import mock

from tests import helpers  # noqa: F401

from storage import db

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _json_files():
    out = []
    for r, _, fs in os.walk(os.environ["EVVP_RAW_DATA_DIR"]):
        out += [os.path.join(r, f) for f in fs if f.endswith(".jsonl")]
    return out


class BrokenPool:
    def __init__(self, *a): raise ConnectionError("could not connect to server: Connection refused")


class FailingCursorPool:
    class _Conn:
        def cursor(self, **kw): return self
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def execute(self, *a, **k): raise RuntimeError('syntax error at or near "INTERVAL"')
        def commit(self): pass
        def rollback(self): pass
    def __init__(self, *a): pass
    def getconn(self): return self._Conn()
    def putconn(self, c): pass


class StrictPostgres(unittest.TestCase):
    def setUp(self):
        helpers.reset_files()
        self._saved = {k: getattr(db, k, None) for k in ("psycopg2", "pg_pool", "PSYCOPG2_AVAILABLE", "DB_URL", "_pool")}
        db.psycopg2 = types.SimpleNamespace(extras=types.SimpleNamespace(Json=lambda o, dumps=None: o, RealDictCursor=object))
        db.PSYCOPG2_AVAILABLE, db.DB_URL, db._pool = True, "postgresql://fake", None
        self.item = {"id": "s1", "platform": "blog", "title": "t", "text": "", "collected_at": "2026-10-06T10:00:00+00:00"}

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(db, k, v)

    def _all_operations_raise(self):
        for fn in (lambda: db.save_raw(dict(self.item)), lambda: db.load_recent_raw(0), lambda: db.update_raw("s1", lambda o: True),
                   lambda: db.append_source("s1", "https://x/1", "blog"), lambda: db.save_verified({"id": "v", "raw_id": "s1"}),
                   lambda: db.save_verification({"id": "r", "raw_id": "s1"}), lambda: db.load_verifications(0), db.check_storage):
            with self.assertRaises(db.StorageError):
                fn()
        self.assertEqual(_json_files(), [], "data was silently written to JSON files while PostgreSQL is configured")

    def test_server_down_every_operation_raises_and_nothing_goes_to_json(self):
        db.pg_pool = types.SimpleNamespace(ThreadedConnectionPool=BrokenPool)
        self._all_operations_raise()

    def test_sql_error_raises_and_nothing_goes_to_json(self):
        db.pg_pool = types.SimpleNamespace(ThreadedConnectionPool=FailingCursorPool)
        self._all_operations_raise()

    def test_driver_missing_with_db_url_is_an_error_not_json(self):
        db.PSYCOPG2_AVAILABLE = False
        for fn in (lambda: db.save_raw(dict(self.item)), lambda: db.load_recent_raw(0), db.check_storage, db.storage_backend):
            with self.assertRaises(db.StorageError) as cm:
                fn()
            self.assertIn("psycopg2", str(cm.exception))
        self.assertEqual(_json_files(), [])

    def test_jsonl_is_used_only_when_no_db_url(self):
        db.DB_URL = ""
        self.assertEqual(db.storage_backend(), "jsonl")
        self.assertEqual(db.check_storage(), "jsonl")
        db.save_raw(dict(self.item))
        self.assertEqual(len(_json_files()), 1)

    def test_collector_reports_storage_failure_instead_of_healthy(self):
        from ingestion import blog
        from source_manager import manager
        db.pg_pool = types.SimpleNamespace(ThreadedConnectionPool=BrokenPool)
        s = manager.add_source({"name": "Feed", "url": "https://feed.example/rss", "type": "rss", "trust": "high"})
        rss = (b'<?xml version="1.0"?><rss version="2.0"><channel><title>F</title><item><title>Acme unauthenticated RCE zero-day exploited in the wild</title>'
               b'<link>https://feed.example/1</link><guid>1</guid><description>Remote code execution, exploited in the wild.</description></item></channel></rss>')

        class R:
            content, status_code, headers = rss, 200, {}
        import pipeline.processor as proc
        proc._recent_cache, proc._cache_counter = [], 0
        with mock.patch.object(blog.manager, "safe_get", return_value=R()):
            self.assertEqual(blog.collect_source(s)[1], 0)
        st = manager.get_source(s["id"])
        self.assertEqual(st["status"], "error")
        self.assertIn("storage error", st["last_error"])
        self.assertEqual(_json_files(), [])

    def test_api_returns_503_and_health_is_degraded(self):
        from api import server
        db.pg_pool = types.SimpleNamespace(ThreadedConnectionPool=BrokenPool)
        server.invalidate()
        c = server.app.test_client()
        h = c.get("/api/health")
        self.assertEqual(h.status_code, 503)
        body = h.get_json()
        self.assertEqual((body["status"], body["storage"]), ("degraded", "postgresql"))
        self.assertIn("Connection refused", body["storage_error"])
        for path in ("/api/vulns", "/api/stats", "/api/cves", "/api/zerodays", "/api/trending"):
            r = c.get(path)
            self.assertEqual(r.status_code, 503, path)
            self.assertTrue(r.get_json()["storage_error"])


class StartupFailsFast(unittest.TestCase):
    def test_app_refuses_to_start_when_postgres_is_configured_but_unusable(self):
        import tempfile
        d = tempfile.mkdtemp()
        env = {**os.environ, "DB_URL": "postgresql://evvp:evvp@127.0.0.1:1/nope", "EVVP_RAW_DATA_DIR": d + "/raw", "EVVP_DATA_DIR": d + "/data",
               "EVVP_LOG_DIR": d + "/logs", "PYTHONPATH": ROOT}
        r = subprocess.run([sys.executable, "main.py", "--api-only"], cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 2, r.stderr[-400:])
        self.assertIn("EVVP cannot start", r.stderr)
        self.assertIn("never silently falls back", r.stderr)
        self.assertFalse(os.path.exists(d + "/raw") and any(f.endswith(".jsonl") for _, _, fs in os.walk(d + "/raw") for f in fs))


if __name__ == "__main__":
    unittest.main()
