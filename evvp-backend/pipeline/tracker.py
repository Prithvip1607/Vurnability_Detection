"""
CVE Trend Tracker — tracks mention counts per CVE across all sources.

Every time a CVE is seen in a collected item, its mention count is incremented.
When a CVE crosses a spike threshold within a short window, it is flagged as
"trending" and a notification is fired.

Storage: in-memory (fast) + JSONL file for persistence across restarts.
"""
from __future__ import annotations

import json
import os
import threading
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Callable

from config.settings import RAW_DATA_DIR
from utils.logger import get_logger

logger = get_logger("tracker")

# ── Config ────────────────────────────────────────────────────────────────────
SPIKE_WINDOW_HOURS  = 6     # look at mentions in last N hours to detect spike
SPIKE_THRESHOLD     = 3     # N mentions in the window = trending
TREND_COOLDOWN_MINS = 60    # don't re-alert the same CVE within N minutes

_PERSIST_PATH = os.path.join(RAW_DATA_DIR, "cve_mentions.jsonl")

# ── State ─────────────────────────────────────────────────────────────────────
# { cve_id: [ {"ts": iso_str, "platform": str, "url": str, "title": str} ] }
_mentions: dict[str, list[dict]] = defaultdict(list)
_last_alerted: dict[str, datetime] = {}   # cve_id -> last alert time
_lock = threading.Lock()

# Registered notification callbacks — pipeline.notifier registers here
_on_trending: list[Callable] = []


def register_trending_callback(fn: Callable) -> None:
    """Register a function to call when a CVE becomes trending."""
    _on_trending.append(fn)


# ── Public API ────────────────────────────────────────────────────────────────

def record(cve_ids: list[str], item: dict) -> None:
    """
    Record a mention of each CVE ID found in an item.
    Checks for spike after recording and fires callbacks if trending.
    """
    if not cve_ids:
        return

    now = datetime.now(timezone.utc)
    mention = {
        "ts":       now.isoformat(),
        "platform": item.get("platform", ""),
        "url":      item.get("url", ""),
        "title":    item.get("title", "")[:200],
    }

    with _lock:
        for cve_id in cve_ids:
            cve_id = cve_id.upper()
            _mentions[cve_id].append(mention)
            _persist_mention(cve_id, mention)
            _check_spike(cve_id, now, item)


def get_trending(hours: int = 24, top_n: int = 20) -> list[dict]:
    """Return top N CVEs by mention count in the last `hours` hours."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    counts: dict[str, int] = {}

    with _lock:
        for cve_id, mentions in _mentions.items():
            recent = [m for m in mentions if _parse_ts(m["ts"]) > cutoff]
            if recent:
                counts[cve_id] = len(recent)

    sorted_cves = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    result = []
    for cve_id, count in sorted_cves[:top_n]:
        with _lock:
            recent_mentions = [
                m for m in _mentions[cve_id]
                if _parse_ts(m["ts"]) > cutoff
            ]
        sources = list({m["platform"] for m in recent_mentions})
        result.append({
            "cve_id":   cve_id,
            "mentions": count,
            "sources":  sources,
            "latest":   recent_mentions[-1] if recent_mentions else {},
        })
    return result


def get_all_mentions(cve_id: str) -> list[dict]:
    with _lock:
        return list(_mentions.get(cve_id.upper(), []))


def load_from_disk() -> None:
    """Load persisted mentions on startup."""
    if not os.path.exists(_PERSIST_PATH):
        return
    loaded = 0
    try:
        with open(_PERSIST_PATH, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    cve_id  = rec.get("cve_id", "").upper()
                    mention = rec.get("mention", {})
                    if cve_id and mention:
                        _mentions[cve_id].append(mention)
                        loaded += 1
                except json.JSONDecodeError:
                    pass
    except OSError:
        pass
    logger.info("Loaded %d CVE mentions from disk", loaded)


# ── Internal ──────────────────────────────────────────────────────────────────

def _check_spike(cve_id: str, now: datetime, item: dict) -> None:
    """Called under _lock. Fires trending callbacks if spike threshold crossed."""
    cutoff  = now - timedelta(hours=SPIKE_WINDOW_HOURS)
    recent  = [m for m in _mentions[cve_id] if _parse_ts(m["ts"]) > cutoff]
    count   = len(recent)

    if count < SPIKE_THRESHOLD:
        return

    last = _last_alerted.get(cve_id)
    if last and (now - last).total_seconds() < TREND_COOLDOWN_MINS * 60:
        return

    _last_alerted[cve_id] = now
    sources = list({m["platform"] for m in recent})
    event = {
        "cve_id":        cve_id,
        "mention_count": count,
        "window_hours":  SPIKE_WINDOW_HOURS,
        "sources":       sources,
        "latest_item":   item,
        "detected_at":   now.isoformat(),
    }
    logger.info("TRENDING: %s — %d mentions in %dh across %s",
                cve_id, count, SPIKE_WINDOW_HOURS, sources)
    for fn in _on_trending:
        try:
            fn(event)
        except Exception as e:
            logger.error("Trending callback error: %s", e)


_persist_lock = threading.Lock()


def _persist_mention(cve_id: str, mention: dict) -> None:
    os.makedirs(os.path.dirname(_PERSIST_PATH), exist_ok=True)
    with _persist_lock:
        try:
            with open(_PERSIST_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps({"cve_id": cve_id, "mention": mention}) + "\n")
        except OSError:
            pass


def _parse_ts(ts: str) -> datetime:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return datetime.min.replace(tzinfo=timezone.utc)
