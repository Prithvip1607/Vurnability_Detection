"""
Storage layer — PostgreSQL (primary) with JSONL file fallback.

Thread-safe:
  - PostgreSQL: ThreadedConnectionPool (min=1, max=10)
  - JSONL: per-file threading.Lock + in-memory seen-ID set
"""
import json
import os
import re
import threading
from contextlib import contextmanager
import uuid
from datetime import datetime, timedelta, timezone
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
from utils.timeutil import parse_ts

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
    collected_at      TIMESTAMPTZ DEFAULT NOW(),
    sources           JSONB DEFAULT '[]',
    summary           TEXT
);
ALTER TABLE intel_raw ADD COLUMN IF NOT EXISTS sources JSONB DEFAULT '[]';
ALTER TABLE intel_raw ADD COLUMN IF NOT EXISTS summary TEXT;
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
            pool = None
            try:
                pool = pg_pool.ThreadedConnectionPool(1, 10, DB_URL)
                conn = pool.getconn()
                try:
                    with conn.cursor() as cur:
                        cur.execute(_SCHEMA)
                    conn.commit()
                finally:
                    pool.putconn(conn)
            except Exception as e:
                if pool is not None:
                    try:
                        pool.closeall()
                    except Exception:
                        pass
                raise StorageError(f"PostgreSQL connection/schema setup failed: {e}") from e
            _pool = pool
    return _pool


class StorageError(RuntimeError):
    """The configured storage backend failed. There is deliberately NO silent fallback to another backend:
    if PostgreSQL is configured and unavailable, callers get this error and must report it."""


def _use_postgres() -> bool:
    if not DB_URL:
        return False
    if not PSYCOPG2_AVAILABLE:
        raise StorageError("DB_URL is set (PostgreSQL requested) but the psycopg2 driver is not installed — "
                           "run `pip install -r requirements-optional.txt` (psycopg2-binary), or unset DB_URL to use JSONL files")
    return True


def storage_backend() -> str:
    return "postgresql" if _use_postgres() else "jsonl"


def check_storage() -> str:
    """Verify the configured backend works (connect + schema for PostgreSQL; writable directory for JSONL).
    Returns the backend name; raises StorageError otherwise. Used for fail-fast startup and /api/health."""
    if _use_postgres():
        try:
            with _conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
        except StorageError:
            raise
        except Exception as e:
            raise StorageError(f"cannot use PostgreSQL: {e}") from e
        return "postgresql"
    try:
        os.makedirs(RAW_DATA_DIR, exist_ok=True)
        probe = os.path.join(RAW_DATA_DIR, ".write-test")
        with open(probe, "w") as f:
            f.write("ok")
        os.remove(probe)
    except OSError as e:
        raise StorageError(f"data directory {RAW_DATA_DIR} is not writable: {e}") from e
    return "jsonl"


# ── Public API ────────────────────────────────────────────────────────────────

DATA_VERSION = 0          # bumped on every write so API caches can invalidate immediately (same-process)


def _bump() -> None:
    global DATA_VERSION
    DATA_VERSION += 1


def save_raw(item: dict[str, Any]) -> None:
    """Persist a scored raw intel item. Idempotent — duplicate IDs are silently ignored."""
    _bump()
    if not item.get("id"):
        item["id"] = str(uuid.uuid4())
    if "collected_at" not in item:
        item["collected_at"] = datetime.now(timezone.utc).isoformat()

    if _use_postgres():
        _pg_save_raw(item)
    else:
        _json_save(item)


def save_verified(record: dict[str, Any]) -> None:
    """Persist a verified/enriched intel record (PostgreSQL table or verified.jsonl)."""
    if not record.get("id"):
        record["id"] = str(uuid.uuid4())
    if _use_postgres():
        _pg_save_verified(record)
    else:
        _append_jsonl(os.path.join(RAW_DATA_DIR, "verified.jsonl"), record)


def load_recent_raw(days: int = 7) -> list[dict]:
    """Load collected items from the active backend. ``days=0`` means no time limit."""
    if _use_postgres():
        return _pg_load_recent(days)
    return _json_load_recent(days)


def append_source(existing_id: str, new_url: str, new_platform: str, extra: dict | None = None) -> None:
    """Attach another evidence source to an existing item (deduplicated by URL).

    ``extra`` keeps what makes the evidence usable later: publisher name, observation time, trust, type.
    """
    entry = {"url": new_url, "platform": new_platform, **(extra or {})}
    update_raw(existing_id, lambda obj: _merge_source(obj, entry))


def _merge_source(obj: dict, entry: dict) -> bool:
    sources = obj.get("sources") or []
    if any(s.get("url") == entry["url"] for s in sources) or entry["url"] == obj.get("url"):
        return False
    sources.append(entry)
    obj["sources"] = sources
    return True


def update_raw(item_id: str, mutate) -> bool:
    """Apply ``mutate(item_dict) -> bool`` to a stored item; persist if it returns True."""
    _bump()
    if _use_postgres():
        return _pg_update_raw(item_id, mutate)
    return _json_update_raw(item_id, mutate)


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
# Enrichment fields have no dedicated column; they live under metadata["_x"] so nothing is lost.
_EXTRA_KEYS = ("cve_ids", "nvd_data", "nvd_status", "epss", "epss_percentile", "epss_data", "kev", "intelligence",
               "cross_source_count", "source_trust", "source_trust_weight", "verification", "collected_at_src")


def _row_to_item(r: dict) -> dict:
    item = dict(r)
    meta = dict(item.get("metadata") or {})
    extra = meta.pop("_x", {}) or {}
    item["metadata"] = meta
    item["text"] = item.pop("body", "") or ""
    for k in ("source_ts", "collected_at"):
        v = item.pop(k, None)
        if v is not None:
            item["timestamp" if k == "source_ts" else "collected_at"] = v.isoformat() if hasattr(v, "isoformat") else v
    if extra.get("timestamp_raw"):
        item["timestamp"] = extra["timestamp_raw"]
    item.update({k: v for k, v in extra.items() if k in _EXTRA_KEYS})
    return item


@contextmanager
def _conn():
    pool = _get_pool()
    conn = pool.getconn()
    try:
        yield conn
    finally:
        pool.putconn(conn)


def _pg_save_raw(item: dict[str, Any]) -> None:
    try:
        meta = dict(item.get("metadata") or {})
        meta["_x"] = {k: item[k] for k in _EXTRA_KEYS if k in item}
        meta["_x"]["timestamp_raw"] = item.get("timestamp")
        ts = parse_ts(item.get("timestamp"))
        with _conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO intel_raw
                        (id, platform, source, title, body, author, source_ts, url,
                         metadata, signal_score, category, matched_signals, negative_signals, sources, summary, collected_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (id) DO NOTHING
                """, (
                    item.get("id"), item.get("platform"), item.get("source"),
                    item.get("title"), item.get("text"), item.get("author"), ts, item.get("url"),
                    psycopg2.extras.Json(meta, dumps=_dumps),
                    item.get("signal_score", 0), item.get("category", ""),
                    psycopg2.extras.Json(item.get("matched_signals", [])),
                    psycopg2.extras.Json(item.get("negative_signals", [])),
                    psycopg2.extras.Json(item.get("sources", []), dumps=_dumps),
                    item.get("summary", ""),
                    parse_ts(item.get("collected_at")) or datetime.now(timezone.utc),
                ))
            conn.commit()
    except StorageError:
        raise
    except Exception as e:
        logger.error("PG save_raw failed (%s): %s", item.get("id"), e)
        raise StorageError(f"PostgreSQL save_raw failed: {e}") from e


def _dumps(o):
    return json.dumps(o, default=str, ensure_ascii=False)


def _pg_save_verified(record: dict[str, Any]) -> None:
    try:
        with _conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO intel_verified
                        (id, raw_id, cve_ids, is_novel, novelty_reason, severity_estimate, metadata)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (id) DO UPDATE SET
                        is_novel=EXCLUDED.is_novel, novelty_reason=EXCLUDED.novelty_reason,
                        severity_estimate=EXCLUDED.severity_estimate, verified_at=NOW()
                """, (
                    record.get("id"), record.get("raw_id"),
                    psycopg2.extras.Json(record.get("cve_ids", [])),
                    record.get("is_novel", False), record.get("novelty_reason", ""),
                    record.get("severity_estimate", ""),
                    psycopg2.extras.Json(record.get("metadata", {}), dumps=_dumps),
                ))
            conn.commit()
    except StorageError:
        raise
    except Exception as e:
        logger.error("PG save_verified failed (%s): %s", record.get("id"), e)
        raise StorageError(f"PostgreSQL save_verified failed: {e}") from e


def _pg_load_recent(days: int) -> list[dict]:
    try:
        with _conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                if days > 0:
                    cur.execute("SELECT * FROM intel_raw WHERE collected_at >= NOW() - make_interval(days => %s) "
                                "ORDER BY collected_at DESC", (days,))
                else:
                    cur.execute("SELECT * FROM intel_raw ORDER BY collected_at DESC")
                return [_row_to_item(r) for r in cur.fetchall()]
    except StorageError:
        raise
    except Exception as e:
        logger.error("PG load_recent failed: %s", e)
        raise StorageError(f"PostgreSQL load failed: {e}") from e


def _pg_update_raw(item_id: str, mutate) -> bool:
    try:
        with _conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM intel_raw WHERE id = %s FOR UPDATE", (item_id,))
                row = cur.fetchone()
                if not row:
                    conn.rollback()
                    return False
                item = _row_to_item(row)
                if not mutate(item):
                    conn.rollback()
                    return False
                meta = dict(item.get("metadata") or {})
                meta["_x"] = {k: item[k] for k in _EXTRA_KEYS if k in item}
                meta["_x"]["timestamp_raw"] = item.get("timestamp")
                cur.execute("UPDATE intel_raw SET metadata=%s, sources=%s, summary=%s WHERE id=%s", (
                    psycopg2.extras.Json(meta, dumps=_dumps),
                    psycopg2.extras.Json(item.get("sources", []), dumps=_dumps),
                    item.get("summary", ""), item_id))
            conn.commit()
            return True
    except StorageError:
        raise
    except Exception as e:
        logger.error("PG update_raw failed (%s): %s", item_id, e)
        raise StorageError(f"PostgreSQL update failed: {e}") from e


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
    platform = re.sub(r"[^a-z0-9_-]", "_", str(item.get("platform") or "unknown").lower())
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


def _jsonl_files() -> list[str]:
    """Every collected-data file, newest first (platform sub-directories are discovered, not hard-coded)."""
    out: list[str] = []
    if not os.path.isdir(RAW_DATA_DIR):
        return out
    for plat in sorted(os.listdir(RAW_DATA_DIR)):
        d = os.path.join(RAW_DATA_DIR, plat)
        if os.path.isdir(d):
            out += [os.path.join(d, fn) for fn in sorted(os.listdir(d), reverse=True) if fn.endswith(".jsonl")]
    return out


def _append_jsonl(path: str, obj: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with _get_file_lock(path):
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(obj, ensure_ascii=False, default=str) + "\n")


def _json_update_raw(item_id: str, mutate) -> bool:
    """Rewrite the one JSONL file holding ``item_id`` (atomic replace)."""
    for path in _jsonl_files():
        with _get_file_lock(path):
            lines, found, changed = [], False, False
            try:
                with open(path, encoding="utf-8") as f:
                    raw_lines = f.read().splitlines()
            except OSError:
                continue
            for line in raw_lines:
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    lines.append(line)            # keep unreadable lines untouched
                    continue
                if obj.get("id") == item_id and not found:
                    found = True
                    if mutate(obj):
                        changed = True
                    lines.append(json.dumps(obj, ensure_ascii=False, default=str))
                else:
                    lines.append(line)
            if found:
                if changed:
                    tmp = path + ".tmp"
                    with open(tmp, "w", encoding="utf-8") as f:
                        f.write("\n".join(lines) + "\n")
                    os.replace(tmp, path)
                return changed
    return False


def _json_load_recent(days: int) -> list[dict]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=days) if days > 0 else None
    items: list[dict] = []
    seen: set[str] = set()
    for path in _jsonl_files():
        try:
            with open(path, encoding="utf-8") as f:
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
                    if cutoff is not None:
                        dt = parse_ts(item.get("collected_at")) or parse_ts(item.get("timestamp"))
                        if dt is None or dt <= cutoff:
                            continue
                    items.append(item)
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
    except StorageError:
        raise
    except Exception as e:
        logger.error("PG save_verification failed: %s", e)
        raise StorageError(f"PostgreSQL save_verification failed: {e}") from e


def _pg_load_verifications(days: int) -> list[dict]:
    try:
        pool = _get_pool()
        conn = pool.getconn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT * FROM intel_verification_results
                    WHERE %s = 0 OR verified_at >= NOW() - make_interval(days => %s)
                    ORDER BY credibility_score DESC, verified_at DESC
                """, (days, days))
                rows = []
                for r in cur.fetchall():
                    item = dict(r)
                    if hasattr(item.get("verified_at"), "isoformat"):
                        item["verified_at"] = item["verified_at"].isoformat()
                    rows.append(item)
                return rows
        finally:
            pool.putconn(conn)
    except StorageError:
        raise
    except Exception as e:
        logger.error("PG load_verifications failed: %s", e)
        raise StorageError(f"PostgreSQL load_verifications failed: {e}") from e


_VR_PATH = os.path.join(RAW_DATA_DIR, "verifications.jsonl")
_vr_lock = threading.Lock()


def _json_save_verification(record: dict[str, Any]) -> None:
    os.makedirs(RAW_DATA_DIR, exist_ok=True)
    with _vr_lock:
        with open(_VR_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")


def _json_load_verifications(days: int) -> list[dict]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=days) if days > 0 else None
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
                except json.JSONDecodeError:
                    continue
                dt = parse_ts(rec.get("verified_at"))
                if cutoff is None or (dt and dt > cutoff):
                    results.append(rec)
    except OSError:
        pass
    results.sort(key=lambda x: x.get("credibility_score", 0), reverse=True)
    return results
