import json
import os
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

try:
    import psycopg2
    import psycopg2.extras
    from psycopg2 import pool as pg_pool
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False

from config.settings import DB_URL, RAW_DATA_DIR
from utils.logger import get_logger

logger = get_logger("storage")
os.makedirs(RAW_DATA_DIR, exist_ok=True)

# Thread-safe connection pool (min=1, max=5 connections)
_pool: "pg_pool.ThreadedConnectionPool | None" = None
_pool_lock = threading.Lock()

# Per-file write locks to prevent concurrent JSONL corruption
_file_locks: dict[str, threading.Lock] = {}
_file_locks_lock = threading.Lock()

# In-memory seen-ID sets per platform date-file to skip duplicate writes
_seen_ids: dict[str, set] = {}
_seen_lock = threading.Lock()


def _get_pool():
    global _pool
    with _pool_lock:
        if _pool is None:
            _pool = pg_pool.ThreadedConnectionPool(1, 5, DB_URL)
            # Ensure schema on first connection
            conn = _pool.getconn()
            try:
                _ensure_schema(conn)
                conn.commit()
            finally:
                _pool.putconn(conn)
    return _pool


def _ensure_schema(conn):
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS raw_intel (
                id               TEXT PRIMARY KEY,
                platform         TEXT,
                source           TEXT,
                title            TEXT,
                text             TEXT,
                author           TEXT,
                timestamp        TIMESTAMPTZ,
                url              TEXT,
                metadata         JSONB,
                signal_score     INTEGER DEFAULT 0,
                category         TEXT,
                matched_signals  JSONB,
                negative_signals JSONB,
                collected_at     TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_raw_intel_platform ON raw_intel(platform)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_raw_intel_score ON raw_intel(signal_score DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_raw_intel_collected ON raw_intel(collected_at DESC)")


def _use_postgres() -> bool:
    return bool(DB_URL) and PSYCOPG2_AVAILABLE


def _get_file_lock(path: str) -> threading.Lock:
    with _file_locks_lock:
        if path not in _file_locks:
            _file_locks[path] = threading.Lock()
        return _file_locks[path]


def save(item: dict[str, Any]) -> None:
    if not item.get("id"):
        item["id"] = str(uuid.uuid4())
    if "collected_at" not in item:
        item["collected_at"] = datetime.now(timezone.utc).isoformat()

    if _use_postgres():
        _save_postgres(item)
    else:
        _save_json(item)


def _save_postgres(item: dict[str, Any]) -> None:
    try:
        pool = _get_pool()
        conn = pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO raw_intel
                        (id, platform, source, title, text, author, timestamp, url,
                         metadata, signal_score, category, matched_signals, negative_signals)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (id) DO NOTHING
                """, (
                    item.get("id"), item.get("platform"), item.get("source"),
                    item.get("title"), item.get("text"), item.get("author"),
                    item.get("timestamp"), item.get("url"),
                    psycopg2.extras.Json(item.get("metadata", {})),
                    item.get("signal_score", 0),
                    item.get("category", ""),
                    psycopg2.extras.Json(item.get("matched_signals", [])),
                    psycopg2.extras.Json(item.get("negative_signals", [])),
                ))
            conn.commit()
            logger.debug("Saved to postgres: %s", item.get("id"))
        finally:
            pool.putconn(conn)
    except Exception as e:
        logger.error("Postgres save failed (%s), falling back to JSON: %s", item.get("id"), e)
        _save_json(item)


def _save_json(item: dict[str, Any]) -> None:
    platform = item.get("platform", "unknown")
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    path = os.path.join(RAW_DATA_DIR, platform, f"{date_str}.jsonl")
    os.makedirs(os.path.dirname(path), exist_ok=True)

    item_id = item.get("id", "")
    cache_key = path

    # Skip if already written this session
    with _seen_lock:
        if cache_key not in _seen_ids:
            _seen_ids[cache_key] = _load_existing_ids(path)
        if item_id and item_id in _seen_ids[cache_key]:
            logger.debug("Skipping duplicate: %s", item_id)
            return
        _seen_ids[cache_key].add(item_id)

    lock = _get_file_lock(path)
    with lock:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(item, ensure_ascii=False, default=str) + "\n")
    logger.debug("Saved to JSON: %s", item_id)


def _load_existing_ids(path: str) -> set:
    """Read existing IDs from a JSONL file to prevent duplicates on restart."""
    ids = set()
    if not os.path.exists(path):
        return ids
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        ids.add(json.loads(line).get("id", ""))
                    except json.JSONDecodeError:
                        pass
    except OSError:
        pass
    return ids
