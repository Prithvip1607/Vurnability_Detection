"""Shared test setup: every test run gets an isolated data/log/raw directory so
tests never touch real collected data or the audit trail."""
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

_TMP = tempfile.mkdtemp(prefix="evvp-test-")
os.environ["EVVP_RAW_DATA_DIR"] = os.path.join(_TMP, "raw")
os.environ["EVVP_LOG_DIR"] = os.path.join(_TMP, "logs")
os.environ["EVVP_DATA_DIR"] = os.path.join(_TMP, "data")
os.environ["EVVP_SOURCES_FILE"] = os.path.join(_TMP, "sources.json")
os.environ["EVVP_DECISIONS_FILE"] = os.path.join(_TMP, "decisions.jsonl")
os.environ["EVVP_ALLOW_PRIVATE_SOURCES"] = "1"
os.environ["NVD_MIN_INTERVAL_SECONDS"] = "0"
os.environ.pop("DB_URL", None)
os.environ.pop("EVVP_API_TOKEN", None)
TMP = _TMP


def reset_files():
    import shutil
    for name in ("sources.json", "decisions.jsonl"):
        path = os.path.join(_TMP, name)
        if os.path.exists(path):
            os.remove(path)
    shutil.rmtree(os.path.join(_TMP, "raw"), ignore_errors=True)
    db = sys.modules.get("storage.db")
    if db is not None:                      # forget in-memory dedupe state of the deleted files
        db._seen_ids.clear()
