import time
from datetime import datetime, timezone

import requests
import feedparser

from config.settings import SUBREDDITS, REDDIT_POLL_INTERVAL
from database.storage import save
from utils.logger import get_logger
from utils.retry import retry
from utils.signal_filter import analyze

logger = get_logger("reddit_collector")

_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}


def _apply_filter(item: dict) -> bool:
    r = analyze(item)
    if not r.passes:
        return False
    item["signal_score"]     = r.signal_score
    item["category"]         = r.category
    item["matched_signals"]  = r.matched_signals
    item["negative_signals"] = r.negative_signals
    save(item)
    return True


@retry(max_attempts=3, base_delay=5.0)
def _fetch_subreddit_json(subreddit: str, limit: int = 100) -> tuple[int, int]:
    url = f"https://www.reddit.com/r/{subreddit}/new.json?limit={limit}"
    r = requests.get(url, headers=_HEADERS, timeout=15)
    r.raise_for_status()

    fetched = saved = 0
    for child in r.json().get("data", {}).get("children", []):
        post = child.get("data", {})
        fetched += 1
        created = datetime.fromtimestamp(post.get("created_utc", 0), tz=timezone.utc).isoformat()
        item = {
            "id": f"reddit_{post.get('id')}",
            "platform": "reddit",
            "source": f"r/{subreddit}",
            "title": post.get("title", ""),
            "text": post.get("selftext", ""),
            "author": post.get("author", "[deleted]"),
            "timestamp": created,
            "url": f"https://www.reddit.com{post.get('permalink', '')}",
            "metadata": {
                "score": post.get("score"),
                "num_comments": post.get("num_comments"),
                "flair": post.get("link_flair_text"),
                "external_url": post.get("url") if not post.get("is_self") else None,
                "subreddit": subreddit,
                "via": "json",
            },
        }
        if _apply_filter(item):
            saved += 1

    logger.info("r/%s — %d fetched, %d passed signal filter", subreddit, fetched, saved)
    return fetched, saved


@retry(max_attempts=3, base_delay=5.0)
def _fetch_subreddit_rss(subreddit: str) -> tuple[int, int]:
    url = f"https://www.reddit.com/r/{subreddit}/new.rss"
    feed = feedparser.parse(url)
    fetched = saved = 0

    for entry in feed.entries:
        fetched += 1
        item = {
            "id": f"reddit_rss_{entry.get('id', entry.link)}",
            "platform": "reddit",
            "source": f"r/{subreddit}",
            "title": entry.get("title", ""),
            "text": entry.get("summary", ""),
            "author": entry.get("author", ""),
            "timestamp": entry.get("published", ""),
            "url": entry.get("link", ""),
            "metadata": {"subreddit": subreddit, "via": "rss"},
        }
        if _apply_filter(item):
            saved += 1

    logger.info("r/%s RSS — %d fetched, %d passed signal filter", subreddit, fetched, saved)
    return fetched, saved


def run_once() -> None:
    for sub in SUBREDDITS:
        try:
            _fetch_subreddit_json(sub)
        except Exception as e:
            logger.warning("JSON failed for r/%s: %s — trying RSS", sub, e)
            try:
                _fetch_subreddit_rss(sub)
            except Exception as e2:
                logger.error("RSS also failed for r/%s: %s", sub, e2)


def run_continuous() -> None:
    logger.info("Reddit collector started (interval=%ds)", REDDIT_POLL_INTERVAL)
    while True:
        try:
            run_once()
        except Exception as e:
            logger.error("Reddit collector cycle error: %s", e)
        time.sleep(REDDIT_POLL_INTERVAL)
