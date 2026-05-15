"""
Storage layer — PostgreSQL (primary) with JSONL file fallback.

Thread-safe:
  - PostgreSQL: ThreadedConnectionPool (min=1, max=10)
  - JSONL: per-file threading.Lock + in-memory seen-ID set
"""
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

# ── PostgreSQL pool ───────────────────────────────────────────────────────────
_pool: "pg_pool.ThreadedConnectionPool | None" = None
_pool_lock = threading.Lock()

# ── JSONL write safety ────────────────────────────────────────────────────────
_file_locks: dict[str, threading.Lock] = {}
_file_locks_mu = threading.Lock()
_seen_ids: dict[str, set] = {}
_seen_mu = threading.Lock()


# ── Schema ────────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS intel_raw (
    id                TEXT PRIMARY KEY,
    platform          TEXT NOT NULL,
    source            TEXT,
    title             TEXT,
    body              TEXT,
    author            TEXT,
    source_ts         TIMESTAMPTZ,
    url               TEXT,
    metadata          JSONB DEFAULT '{}',
    signal_score      INTEGER DEFAULT 0,
    category          TEXT,
    matched_signals   JSONB DEFAULT '[]',
    negative_signals  JSONB DEFAULT '[]',
    collected_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_intel_platform    ON intel_raw(platform);
CREATE INDEX IF NOT EXISTS idx_intel_score       ON intel_raw(signal_score DESC);
CREATE INDEX IF NOT EXISTS idx_intel_collected   ON intel_raw(collected_at DESC);
CREATE INDEX IF NOT EXISTS idx_intel_category    ON intel_raw(category);

CREATE TABLE IF NOT EXISTS intel_verified (
    id                TEXT PRIMARY KEY,
    raw_id            TEXT REFERENCES intel_raw(id),
    cve_ids           JSONB DEFAULT '[]',
    is_novel          BOOLEAN DEFAULT FALSE,
    novelty_reason    TEXT,
    severity_estimate TEXT,
    verified_at       TIMESTAMPTZ DEFAULT NOW(),
    metadata          JSONB DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_verified_novel    ON intel_verified(is_novel);
CREATE INDEX IF NOT EXISTS idx_verified_ts       ON intel_verified(verified_at DESC);

CREATE TABLE IF NOT EXISTS intel_verification_results (
    id                   TEXT PRIMARY KEY,
    raw_id               TEXT,
    poc_found            BOOLEAN DEFAULT FALSE,
    poc_signals          JSONB DEFAULT '[]',
    affected_products    JSONB DEFAULT '[]',
    credibility_score    INTEGER DEFAULT 0,
    credibility_notes    JSONB DEFAULT '[]',
    in_nvd               BOOLEAN DEFAULT FALSE,
    in_nvd_at            TEXT,
    cross_source_count   INTEGER DEFAULT 1,
    verification_status  TEXT DEFAULT 'unverified',
    verified_at          TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_vr_raw_id ON intel_verification_results(raw_id);
CREATE INDEX IF NOT EXISTS idx_vr_status ON intel_verification_results(verification_status);
CREATE INDEX IF NOT EXISTS idx_vr_cred   ON intel_verification_results(credibility_score DESC);
"""


# ── Pool management ───────────────────────────────────────────────────────────

def _get_pool() -> "pg_pool.ThreadedConnectionPool":
    global _pool
    with _pool_lock:
        if _pool is None:
            _pool = pg_pool.ThreadedConnectionPool(1, 10, DB_URL)
            conn = _pool.getconn()
            try:
                with conn.cursor() as cur:
                    cur.execute(_SCHEMA)
                conn.commit()
            finally:
                _pool.putconn(conn)
    return _pool


def _use_postgres() -> bool:
    return bool(DB_URL) and PSYCOPG2_AVAILABLE


# ── Public API ────────────────────────────────────────────────────────────────

def save_raw(item: dict[str, Any]) -> None:
    """Persist a scored raw intel item. Idempotent — duplicate IDs are silently ignored."""
    if not item.get("id"):
        item["id"] = str(uuid.uuid4())
    if "collected_at" not in item:
        item["collected_at"] = datetime.now(timezone.utc).isoformat()

    if _use_postgres():
        _pg_save_raw(item)
    else:
        _json_save(item)


def save_verified(record: dict[str, Any]) -> None:
    """Persist a verified/enriched intel record (PostgreSQL only)."""
    if not _use_postgres():
        logger.warning("save_verified called but no PostgreSQL configured — skipping")
        return
    if not record.get("id"):
        record["id"] = str(uuid.uuid4())
    _pg_save_verified(record)


def load_recent_raw(days: int = 7) -> list[dict]:
    """Load recent raw items from whichever backend is active."""
    if _use_postgres():
        return _pg_load_recent(days)
    return _json_load_recent(days)


def save_verification(record: dict[str, Any]) -> None:
    """Persist a Phase 3 verification result."""
    if not record.get("id"):
        import uuid
        record["id"] = str(uuid.uuid4())
    if _use_postgres():
        _pg_save_verification(record)
    else:
        _json_save_verification(record)


def load_verifications(days: int = 7) -> list[dict]:
    """Load recent verification results."""
    if _use_postgres():
        return _pg_load_verifications(days)
    return _json_load_verifications(days)


# ── PostgreSQL helpers ────────────────────────────────────────────────────────

def _pg_save_raw(item: dict[str, Any]) -> None:
    try:
        pool = _get_pool()
        conn = pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO intel_raw
                        (id, platform, source, title, body, author, source_ts, url,
                         metadata, signal_score, category, matched_signals, negative_signals)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (id) DO NOTHING
                """, (
                    item.get("id"), item.get("platform"), item.get("source"),
                    item.get("title"), item.get("text"), item.get("author"),
                    item.get("timestamp"), item.get("url"),
                    psycopg2.extras.Json(item.get("metadata", {})),
                    item.get("signal_score", 0), item.get("category", ""),
                    psycopg2.extras.Json(item.get("matched_signals", [])),
                    psycopg2.extras.Json(item.get("negative_signals", [])),
                ))
            conn.commit()
        finally:
            pool.putconn(conn)
    except Exception as e:
        logger.error("PG save_raw failed (%s): %s — falling back to JSON", item.get("id"), e)
        _json_save(item)


def _pg_save_verified(record: dict[str, Any]) -> None:
    try:
        pool = _get_pool()
        conn = pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO intel_verified
                        (id, raw_id, cve_ids, is_novel, novelty_reason, severity_estimate, metadata)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (id) DO UPDATE SET
                        is_novel=EXCLUDED.is_novel,
                        novelty_reason=EXCLUDED.novelty_reason,
                        severity_estimate=EXCLUDED.severity_estimate,
                        verified_at=NOW()
                """, (
                    record.get("id"), record.get("raw_id"),
                    psycopg2.extras.Json(record.get("cve_ids", [])),
                    record.get("is_novel", False),
                    record.get("novelty_reason", ""),
                    record.get("severity_estimate", ""),
                    psycopg2.extras.Json(record.get("metadata", {})),
                ))
            conn.commit()
        finally:
            pool.putconn(conn)
    except Exception as e:
        logger.error("PG save_verified failed (%s): %s", record.get("id"), e)


def _pg_load_recent(days: int) -> list[dict]:
    try:
        pool = _get_pool()
        conn = pool.getconn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT * FROM intel_raw
                    WHERE collected_at >= NOW() - INTERVAL '%s days'
                    ORDER BY signal_score DESC, collected_at DESC
                """, (days,))
                return [dict(r) for r in cur.fetchall()]
        finally:
            pool.putconn(conn)
    except Exception as e:
        logger.error("PG load_recent failed: %s — falling back to JSON", e)
        return _json_load_recent(days)


# ── JSONL helpers ─────────────────────────────────────────────────────────────

def _get_file_lock(path: str) -> threading.Lock:
    with _file_locks_mu:
        if path not in _file_locks:
            _file_locks[path] = threading.Lock()
        return _file_locks[path]


def _existing_ids(path: str) -> set:
    ids: set = set()
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


def _json_save(item: dict[str, Any]) -> None:
    platform = item.get("platform", "unknown")
    date_str  = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    path      = os.path.join(RAW_DATA_DIR, platform, f"{date_str}.jsonl")
    os.makedirs(os.path.dirname(path), exist_ok=True)

    item_id = item.get("id", "")
    with _seen_mu:
        if path not in _seen_ids:
            _seen_ids[path] = _existing_ids(path)
        if item_id and item_id in _seen_ids[path]:
            return
        _seen_ids[path].add(item_id)

    with _get_file_lock(path):
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(item, ensure_ascii=False, default=str) + "\n")
    logger.debug("JSON saved: %s", item_id)


def _json_load_recent(days: int) -> list[dict]:
    from datetime import timedelta
    cutoff = datetime.now() - timedelta(days=days)
    items: list[dict] = []
    seen: set[str] = set()

    for platform in ("reddit", "github", "blog", "nvd"):
        d = os.path.join(RAW_DATA_DIR, platform)
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d), reverse=True):
            if not fn.endswith(".jsonl"):
                continue
            try:
                with open(os.path.join(d, fn), encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            item = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        uid = item.get("id") or item.get("url", "")
                        if uid in seen:
                            continue
                        seen.add(uid)
                        ts_str = item.get("collected_at") or item.get("timestamp", "")
                        try:
                            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                            if dt.replace(tzinfo=None) > cutoff:
                                items.append(item)
                        except Exception:
                            pass
            except OSError:
                pass
    return items


def _pg_save_verification(record: dict[str, Any]) -> None:
    try:
        pool = _get_pool()
        conn = pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO intel_verification_results
                        (id, raw_id, poc_found, poc_signals, affected_products,
                         credibility_score, credibility_notes, in_nvd, in_nvd_at,
                         cross_source_count, verification_status)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (id) DO UPDATE SET
                        credibility_score=EXCLUDED.credibility_score,
                        verification_status=EXCLUDED.verification_status,
                        verified_at=NOW()
                """, (
                    record.get("id"), record.get("raw_id"),
                    record.get("poc_found", False),
                    psycopg2.extras.Json(record.get("poc_signals", [])),
                    psycopg2.extras.Json(record.get("affected_products", [])),
                    record.get("credibility_score", 0),
                    psycopg2.extras.Json(record.get("credibility_notes", [])),
                    record.get("in_nvd", False),
                    record.get("in_nvd_at", ""),
                    record.get("cross_source_count", 1),
                    record.get("verification_status", "unverified"),
                ))
            conn.commit()
        finally:
            pool.putconn(conn)
    except Exception as e:
        logger.error("PG save_verification failed: %s", e)
        _json_save_verification(record)


def _pg_load_verifications(days: int) -> list[dict]:
    try:
        pool = _get_pool()
        conn = pool.getconn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT * FROM intel_verification_results
                    WHERE verified_at >= NOW() - INTERVAL '%s days'
                    ORDER BY credibility_score DESC, verified_at DESC
                """, (days,))
                return [dict(r) for r in cur.fetchall()]
        finally:
            pool.putconn(conn)
    except Exception as e:
        logger.error("PG load_verifications failed: %s", e)
        return _json_load_verifications(days)


_VR_PATH = os.path.join(RAW_DATA_DIR, "verifications.jsonl")
_vr_lock = threading.Lock()


def _json_save_verification(record: dict[str, Any]) -> None:
    os.makedirs(RAW_DATA_DIR, exist_ok=True)
    with _vr_lock:
        with open(_VR_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")


def _json_load_verifications(days: int) -> list[dict]:
    from datetime import timedelta
    cutoff = datetime.now() - timedelta(days=days)
    results: list[dict] = []
    if not os.path.exists(_VR_PATH):
        return results
    try:
        with open(_VR_PATH, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    ts_str = rec.get("verified_at", "")
                    dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    if dt.replace(tzinfo=None) > cutoff:
                        results.append(rec)
                except Exception:
                    pass
    except OSError:
        pass
    results.sort(key=lambda x: x.get("credibility_score", 0), reverse=True)
    return results
