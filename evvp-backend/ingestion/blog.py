"""Blog / RSS / Atom ingestion, driven entirely by the Source Manager.

Every enabled RSS/Atom source is collected on its own interval. A failing source is recorded
(status, last_error, consecutive_failures, exponential back-off) and never stops the others.
"""
from __future__ import annotations

import hashlib
import html
import re
import time

import requests  # noqa: F401  (patched in tests; manager.safe_get uses the same module)

from config.settings import TICK_SECONDS, TRUST_WEIGHT
from ingestion.feedparse import parse_feed
from ingestion.jsonapi import parse_json_feed
from pipeline.processor import process
from source_manager import manager
from storage.db import StorageError
from utils.audit import audit, EV_SOURCE_COLLECTED, EV_SOURCE_FETCH_FAIL
from utils.logger import get_logger

logger = get_logger("ingestion.blog")
MAX_ENTRIES = 200


def _to_plain(raw: str) -> str:
    text = re.sub(r"<[^>]+>", " ", raw or "")
    text = html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def _item_id(feed_url: str, entry_id: str) -> str:
    return "blog_" + hashlib.sha1(f"{feed_url}::{entry_id}".encode()).hexdigest()


def _build_item(src: dict, feed: dict, entry: dict) -> dict:
    entry_id = entry.get("id") or entry.get("link") or entry.get("title", "")
    trust = src.get("trust") or "medium"
    return {
        "id": _item_id(src["url"], entry_id),
        "platform": "blog",
        "source": feed.get("feed_link") or src["url"],
        "title": (entry.get("title") or "").strip(),
        "text": _to_plain(entry.get("content", "")),
        "author": entry.get("author", ""),
        "timestamp": entry.get("published", ""),          # never invented: empty stays empty
        "url": entry.get("link", ""),
        "source_trust": trust,
        "source_trust_weight": TRUST_WEIGHT.get(trust, 55),
        "metadata": {
            "feed_url": src["url"], "feed_title": feed.get("feed_title", ""), "tags": entry.get("tags", []),
            "source_id": src["id"], "source_name": src["name"], "source_category": src.get("category", "news"), "source_type": src["type"],
            "source_trust": trust,
        },
    }


def collect_source(src: dict) -> tuple[int, int]:
    """Collect one source. Returns (entries fetched, findings saved). Never raises."""
    sid = src["id"]
    try:
        resp = manager.safe_get(src["url"])
        feed = (parse_json_feed(resp.content, src.get("mapping"), src["name"], src["url"]) if src["type"] in ("api", "custom")
                else parse_feed(resp.content))
    except Exception as exc:                              # network, HTTP, SSRF guard, invalid XML ...
        msg = str(exc) or exc.__class__.__name__
        manager.mark_fetch(sid, success=False, error=msg)
        audit(EV_SOURCE_FETCH_FAIL, source=src["name"], source_id=sid, error=msg[:300])
        logger.warning("Source %s failed: %s", src["name"], msg)
        return 0, 0
    fetched = saved = 0
    for entry in feed["entries"][:MAX_ENTRIES]:
        fetched += 1
        try:
            if process(_build_item(src, feed, entry)):
                saved += 1
        except StorageError as exc:                       # storage is broken: say so, do not report a healthy collection
            manager.mark_fetch(sid, success=False, error=f"storage error: {exc}")
            audit(EV_SOURCE_FETCH_FAIL, source=src["name"], source_id=sid, error=f"storage error: {exc}"[:300])
            logger.error("Source %s: storage error, collection aborted: %s", src["name"], exc)
            return fetched, saved
        except Exception as exc:                          # one malformed entry must not lose the rest
            logger.error("Entry from %s skipped: %s", src["name"], exc)
    manager.mark_fetch(sid, success=True, item_count=fetched, new_items=saved)
    audit(EV_SOURCE_COLLECTED, source=src["name"], source_id=sid, fetched=fetched, saved=saved)
    logger.info("Source %s — %d fetched, %d saved", src["name"], fetched, saved)
    return fetched, saved


def run_once(force: bool = False) -> None:
    for src in manager.enabled_feeds():
        if force or manager.due(src):
            try:
                collect_source(src)
            except Exception as exc:                      # defence in depth
                logger.error("Source %s crashed: %s", src.get("name"), exc)


def run_continuous() -> None:
    logger.info("Blog/RSS collector started (checks which sources are due every %ds)", TICK_SECONDS)
    while True:
        try:
            run_once()
        except Exception as exc:
            logger.error("Blog cycle error: %s", exc)
        time.sleep(TICK_SECONDS)
