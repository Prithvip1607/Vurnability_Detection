"""
Audit Logger — writes a structured audit trail of every significant
action the system takes: items collected, pipeline decisions, notifications
fired, errors, and system lifecycle events.

Every audit entry is written to:
  logs/audit.jsonl   — machine-readable (one JSON per line)
  logs/audit.log     — human-readable rotating log

Usage (anywhere in the codebase):
    from utils.audit import audit
    audit("item_collected",  platform="reddit", title="...", score=18)
    audit("item_dropped",    platform="github", reason="low_score", score=3)
    audit("notification_sent", channel="webhook", cve_id="CVE-2024-1234")
    audit("trending_detected", cve_id="CVE-2024-1234", mentions=5, sources=["reddit","blog"])
    audit("system_start",    workers=["reddit","github","blog","nvd"])
    audit("system_stop",     reason="SIGINT")
    audit("error",           module="ingestion.github", message="rate limit hit")
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
import logging

# ── Paths ─────────────────────────────────────────────────────────────────────
_BASE    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_LOG_DIR = os.getenv("EVVP_LOG_DIR") or os.path.join(_BASE, "logs")
os.makedirs(_LOG_DIR, exist_ok=True)

_JSONL_PATH = os.path.join(_LOG_DIR, "audit.jsonl")
_LOG_PATH   = os.path.join(_LOG_DIR, "audit.log")

# ── Human-readable rotating log ───────────────────────────────────────────────
_logger = logging.getLogger("audit")
if not _logger.handlers:
    _logger.setLevel(logging.INFO)
    _fmt = logging.Formatter("%(asctime)s [AUDIT] %(message)s")
    try:
        fh = RotatingFileHandler(_LOG_PATH, maxBytes=10 * 1024 * 1024, backupCount=5)
        fh.setFormatter(_fmt)
        _logger.addHandler(fh)
    except OSError:
        pass
    _logger.propagate = False        # human-readable lines go to the audit.log file only; the console stays quiet

# ── JSONL write lock ──────────────────────────────────────────────────────────
_lock = threading.Lock()

# ── Counters (in-memory stats) ────────────────────────────────────────────────
_stats: dict[str, int] = {
    "items_collected": 0,
    "items_passed":    0,
    "items_dropped":   0,
    "notifications":   0,
    "trending_alerts": 0,
    "errors":          0,
}
_stats_lock = threading.Lock()


# ── Public API ────────────────────────────────────────────────────────────────

def audit(event: str, **kwargs) -> None:
    """
    Write one audit entry.

    event       — short snake_case event name (see constants below)
    **kwargs    — any additional context fields
    """
    now = datetime.now(timezone.utc)
    entry = {
        "ts":    now.isoformat(),
        "event": event,
        **{k: v for k, v in kwargs.items() if v is not None},
    }

    # Update in-memory counters
    _update_stats(event)

    # Write JSONL
    with _lock:
        try:
            with open(_JSONL_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
        except OSError:
            pass

    # Write human-readable log
    _log_human(event, entry)


def get_stats() -> dict:
    """Return current in-memory counters — used by the API /api/audit/stats."""
    with _stats_lock:
        return dict(_stats)


def get_recent(n: int = 100, event: str | None = None, q: str | None = None) -> list[dict]:
    """Return the last N audit entries (optionally filtered by event name / free text)."""
    entries = []
    if not os.path.exists(_JSONL_PATH):
        return entries
    try:
        with open(_JSONL_PATH, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except OSError:
        pass
    if event:
        entries = [e for e in entries if e.get("event") == event]
    if q:
        ql = q.lower()
        entries = [e for e in entries if ql in json.dumps(e, default=str).lower()]
    return entries[-n:]


# ── Internal ──────────────────────────────────────────────────────────────────

def _update_stats(event: str) -> None:
    with _stats_lock:
        if event in ("item_collected",):
            _stats["items_collected"] += 1
        elif event == "item_passed":
            _stats["items_passed"] += 1
        elif event == "item_dropped":
            _stats["items_dropped"] += 1
        elif event == "notification_sent":
            _stats["notifications"] += 1
        elif event == "trending_detected":
            _stats["trending_alerts"] += 1
        elif event in ("error", "worker_error", "source_fetch_fail", "nvd_fetch_fail"):
            _stats["errors"] += 1


def _log_human(event: str, entry: dict) -> None:
    """Format a readable one-liner for the rotating log."""
    parts = [f"event={event}"]
    for key in ("platform", "actor", "source", "cve_id", "title", "score", "severity", "status",
                "reason", "channel", "mentions", "sources", "module", "message"):
        val = entry.get(key)
        if val is not None:
            if isinstance(val, str) and len(val) > 80:
                val = val[:80] + "..."
            parts.append(f"{key}={val!r}")
    _logger.info(" | ".join(parts))


# ── Event name constants (import these for typo safety) ──────────────────────
EV_SYSTEM_START       = "system_start"
EV_SYSTEM_STOP        = "system_stop"
EV_WORKER_START       = "worker_start"
EV_WORKER_ERROR       = "worker_error"
EV_ITEM_COLLECTED     = "item_collected"
EV_ITEM_PASSED        = "item_passed"
EV_ITEM_DROPPED       = "item_dropped"
EV_ITEM_DUPLICATE     = "item_duplicate"
EV_ITEM_NOVEL         = "item_novel"
EV_NOVELTY_SKIP       = "novelty_skip"
EV_NVD_ENRICHED       = "nvd_enriched"
EV_NVD_FETCH_FAIL     = "nvd_fetch_fail"
EV_TRENDING_DETECTED  = "trending_detected"
EV_NOTIFICATION_SENT  = "notification_sent"
EV_NOTIFICATION_FAIL  = "notification_fail"
EV_STORAGE_SAVED      = "storage_saved"
EV_STORAGE_FAIL       = "storage_fail"
EV_ERROR              = "error"

# Source Manager
EV_SOURCE_ADDED       = "source_added"
EV_SOURCE_EDITED      = "source_edited"
EV_SOURCE_ENABLED     = "source_enabled"
EV_SOURCE_DISABLED    = "source_disabled"
EV_SOURCE_DELETED     = "source_deleted"
EV_SOURCE_TESTED      = "source_tested"
EV_SOURCE_FETCH_FAIL  = "source_fetch_fail"
EV_SOURCE_COLLECT_TRIGGERED = "source_collect_triggered"   # analyst pressed "Collect now"
EV_SOURCE_COLLECTED   = "source_collected"                 # a collection finished (manual or scheduled)
# Analyst workflow
EV_FINDING_REVIEWED   = "finding_reviewed"
EV_FINDING_CONFIRMED  = "finding_confirmed"
EV_FINDING_FALSE_POS  = "finding_false_positive"
EV_FINDING_RESOLVED   = "finding_resolved"
EV_ANALYST_NOTE       = "analyst_note_added"
