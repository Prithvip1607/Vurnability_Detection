import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any

try:
    import psycopg2
    import psycopg2.extras
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False

from config.settings import DB_URL, RAW_DATA_DIR
from utils.logger import get_logger

logger = get_logger("storage")
os.makedirs(RAW_DATA_DIR, exist_ok=True)

_conn = None


def _get_conn():
    global _conn
    if _conn is None or _conn.closed:
        _conn = psycopg2.connect(DB_URL)
        _conn.autocommit = True
        _ensure_schema(_conn)
    return _conn


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


def _use_postgres() -> bool:
    return bool(DB_URL) and PSYCOPG2_AVAILABLE


def save(item: dict[str, Any]) -> None:
    if "id" not in item or not item["id"]:
        item["id"] = str(uuid.uuid4())
    if "collected_at" not in item:
        item["collected_at"] = datetime.now(timezone.utc).isoformat()

    if _use_postgres():
        _save_postgres(item)
    else:
        _save_json(item)


def _save_postgres(item: dict[str, Any]) -> None:
    try:
        conn = _get_conn()
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
        logger.debug("Saved to postgres: %s", item.get("id"))
    except Exception as e:
        logger.error("Postgres save failed (%s), falling back to JSON: %s", item.get("id"), e)
        _save_json(item)


def _save_json(item: dict[str, Any]) -> None:
    platform = item.get("platform", "unknown")
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    path = os.path.join(RAW_DATA_DIR, platform, f"{date_str}.jsonl")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(item, ensure_ascii=False, default=str) + "\n")
    logger.debug("Saved to JSON: %s", item.get("id"))
