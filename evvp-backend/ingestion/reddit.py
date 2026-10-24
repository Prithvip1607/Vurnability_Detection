"""
Reddit ingestion — public JSON endpoint with RSS fallback.
No credentials required.
"""
import time
from datetime import datetime, timezone

import requests

from config.settings import TICK_SECONDS
from config.settings import REDDIT_BASE_URL, SUBREDDITS
from ingestion.feedparse import parse_feed
from pipeline.processor import process
from source_manager import manager
from utils.audit import audit, EV_SOURCE_FETCH_FAIL
from utils.logger import get_logger
from utils.retry import retry

logger = get_logger("ingestion.reddit")

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; EVVP/1.0)"}


def _build_item(post: dict, subreddit: str) -> dict:
    created = datetime.fromtimestamp(post.get("created_utc", 0), tz=timezone.utc).isoformat()
    return {
        "id":       f"reddit_{post.get('id')}",
        "platform": "reddit",
        "source":   f"r/{subreddit}",
        "title":    post.get("title", ""),
        "text":     post.get("selftext", ""),
        "author":   post.get("author", "[deleted]"),
        "timestamp": created,
        "url":      f"{REDDIT_BASE_URL}{post.get('permalink', '')}",
        "metadata": {
            "score":        post.get("score"),
            "num_comments": post.get("num_comments"),
            "flair":        post.get("link_flair_text"),
            "external_url": post.get("url") if not post.get("is_self") else None,
            "subreddit":    subreddit,
            "via":          "json",
        },
    }


@retry(max_attempts=2, base_delay=3.0)
def _fetch_json(subreddit: str) -> tuple[int, int]:
    url = f"{REDDIT_BASE_URL}/r/{subreddit}/new.json?limit=100"
    r = requests.get(url, headers=_HEADERS, timeout=15)
    r.raise_for_status()
    fetched = saved = 0
    for child in r.json().get("data", {}).get("children", []):
        fetched += 1
        if process(_build_item(child.get("data", {}), subreddit)):
            saved += 1
    logger.info("r/%s JSON — %d fetched, %d saved", subreddit, fetched, saved)
    return fetched, saved


@retry(max_attempts=2, base_delay=3.0)
def _fetch_rss(subreddit: str) -> tuple[int, int]:
    r = requests.get(f"{REDDIT_BASE_URL}/r/{subreddit}/new.rss", headers=_HEADERS, timeout=15)
    r.raise_for_status()
    feed = parse_feed(r.content)
    fetched = saved = 0
    for entry in feed["entries"]:
        fetched += 1
        item = {
            "id":       f"reddit_rss_{entry.get('id') or entry.get('link')}",
            "platform": "reddit",
            "source":   f"r/{subreddit}",
            "title":    entry.get("title", ""),
            "text":     entry.get("content", ""),
            "author":   entry.get("author", ""),
            "timestamp": entry.get("published", ""),
            "url":      entry.get("link", ""),
            "metadata": {"subreddit": subreddit, "via": "rss"},
        }
        if process(item):
            saved += 1
    logger.info("r/%s RSS — %d fetched, %d saved", subreddit, fetched, saved)
    return fetched, saved


def run_once(force: bool = False) -> None:
    if not manager.gate("builtin-reddit", force):
        return
    ok = failed = 0
    last_error = ""
    for sub in SUBREDDITS:
        try:
            _fetch_json(sub)
            ok += 1
        except Exception as e:
            logger.warning("JSON failed r/%s: %s — trying RSS", sub, e)
            try:
                _fetch_rss(sub)
                ok += 1
            except Exception as e2:
                failed += 1
                last_error = str(e2)
                logger.error("RSS also failed r/%s: %s", sub, e2)
    if ok == 0 and failed:
        manager.mark_fetch("builtin-reddit", success=False, error=f"all subreddits failed: {last_error}")
        audit(EV_SOURCE_FETCH_FAIL, source="Reddit", source_id="builtin-reddit", error=last_error[:300])
    else:
        manager.mark_fetch("builtin-reddit", success=True, item_count=ok)


def run_continuous() -> None:
    logger.info("Reddit collector started (interval comes from the Source Manager)")
    while True:
        try:
            run_once()
        except Exception as e:
            logger.error("Reddit cycle error: %s", e)
        time.sleep(TICK_SECONDS)
