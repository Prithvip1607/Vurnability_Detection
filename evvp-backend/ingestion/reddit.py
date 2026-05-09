"""
Reddit ingestion — public JSON endpoint with RSS fallback.
No credentials required.
"""
import time
from datetime import datetime, timezone

import feedparser
import requests

from config.settings import SUBREDDITS, REDDIT_POLL_INTERVAL
from pipeline.processor import process
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
        "url":      f"https://www.reddit.com{post.get('permalink', '')}",
        "metadata": {
            "score":        post.get("score"),
            "num_comments": post.get("num_comments"),
            "flair":        post.get("link_flair_text"),
            "external_url": post.get("url") if not post.get("is_self") else None,
            "subreddit":    subreddit,
            "via":          "json",
        },
    }


@retry(max_attempts=3, base_delay=5.0)
def _fetch_json(subreddit: str) -> tuple[int, int]:
    url = f"https://www.reddit.com/r/{subreddit}/new.json?limit=100"
    r = requests.get(url, headers=_HEADERS, timeout=15)
    r.raise_for_status()
    fetched = saved = 0
    for child in r.json().get("data", {}).get("children", []):
        fetched += 1
        if process(_build_item(child.get("data", {}), subreddit)):
            saved += 1
    logger.info("r/%s JSON — %d fetched, %d saved", subreddit, fetched, saved)
    return fetched, saved


@retry(max_attempts=3, base_delay=5.0)
def _fetch_rss(subreddit: str) -> tuple[int, int]:
    feed = feedparser.parse(f"https://www.reddit.com/r/{subreddit}/new.rss")
    fetched = saved = 0
    for entry in feed.entries:
        fetched += 1
        item = {
            "id":       f"reddit_rss_{entry.get('id', entry.link)}",
            "platform": "reddit",
            "source":   f"r/{subreddit}",
            "title":    entry.get("title", ""),
            "text":     entry.get("summary", ""),
            "author":   entry.get("author", ""),
            "timestamp": entry.get("published", ""),
            "url":      entry.get("link", ""),
            "metadata": {"subreddit": subreddit, "via": "rss"},
        }
        if process(item):
            saved += 1
    logger.info("r/%s RSS — %d fetched, %d saved", subreddit, fetched, saved)
    return fetched, saved


def run_once() -> None:
    for sub in SUBREDDITS:
        try:
            _fetch_json(sub)
        except Exception as e:
            logger.warning("JSON failed r/%s: %s — trying RSS", sub, e)
            try:
                _fetch_rss(sub)
            except Exception as e2:
                logger.error("RSS also failed r/%s: %s", sub, e2)


def run_continuous() -> None:
    logger.info("Reddit ingestion started (interval=%ds)", REDDIT_POLL_INTERVAL)
    while True:
        try:
            run_once()
        except Exception as e:
            logger.error("Reddit cycle error: %s", e)
        time.sleep(REDDIT_POLL_INTERVAL)
