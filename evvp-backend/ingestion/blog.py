"""
Blog / RSS ingestion — 18 security feeds.
"""
import hashlib
import html
import re
import time

import feedparser
import requests

from config.settings import RSS_FEEDS, BLOG_POLL_INTERVAL
from pipeline.processor import process
from utils.logger import get_logger
from utils.retry import retry

logger = get_logger("ingestion.blog")
_HEADERS = {"User-Agent": "EVVP/1.0 (RSS Collector)"}


def _to_plain(raw: str) -> str:
    """Strip HTML tags and decode entities to plain text."""
    text = re.sub(r"<[^>]+>", " ", raw)        # remove tags
    text = html.unescape(text)                   # &amp; &lt; etc.
    text = re.sub(r"\s+", " ", text).strip()    # collapse whitespace
    return text


def _item_id(feed_url: str, entry_id: str) -> str:
    return "blog_" + hashlib.sha1(f"{feed_url}::{entry_id}".encode()).hexdigest()


@retry(max_attempts=3, base_delay=10.0)
def _fetch_feed(feed_url: str) -> tuple[int, int]:
    try:
        r = requests.get(feed_url, headers=_HEADERS, timeout=20)
        r.raise_for_status()
        feed = feedparser.parse(r.content)
    except requests.RequestException:
        feed = feedparser.parse(feed_url)

    fetched = saved = 0
    for entry in feed.entries:
        fetched += 1
        entry_id  = entry.get("id") or entry.get("link", "")
        published = entry.get("published") or entry.get("updated") or entry.get("created") or ""
        content = ""
        if entry.get("content"):
            content = entry.content[0].get("value", "")
        elif entry.get("summary"):
            content = entry.summary
        content = _to_plain(content)

        item = {
            "id":       _item_id(feed_url, entry_id),
            "platform": "blog",
            "source":   feed.feed.get("link") or feed_url,
            "title":    entry.get("title", ""),
            "text":     content,
            "author":   entry.get("author", ""),
            "timestamp": published,
            "url":      entry.get("link", ""),
            "metadata": {
                "feed_url":   feed_url,
                "feed_title": feed.feed.get("title", ""),
                "tags":       [t.get("term", "") for t in entry.get("tags", [])],
            },
        }
        if process(item):
            saved += 1
    logger.info("Feed %s — %d fetched, %d saved", feed_url, fetched, saved)
    return fetched, saved


def run_once() -> None:
    for feed_url in RSS_FEEDS:
        try:
            _fetch_feed(feed_url)
        except Exception as e:
            logger.error("Feed failed %s: %s", feed_url, e)


def run_continuous() -> None:
    logger.info("Blog ingestion started (interval=%ds)", BLOG_POLL_INTERVAL)
    while True:
        try:
            run_once()
        except Exception as e:
            logger.error("Blog cycle error: %s", e)
        time.sleep(BLOG_POLL_INTERVAL)
