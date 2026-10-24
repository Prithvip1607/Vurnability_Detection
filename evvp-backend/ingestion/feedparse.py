"""Uniform RSS/Atom parsing.

Uses ``feedparser`` when available. If it is not installed (or chokes), a small
stdlib fallback handles RSS 2.0 and Atom so the collectors and the Source
Manager's "Test" button keep working. The fallback refuses documents that
declare DTD/entities (XML bomb / XXE protection).
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any

try:  # pragma: no cover - exercised only when feedparser is installed
    import feedparser as _fp
except ImportError:  # pragma: no cover
    _fp = None

_ATOM = "{http://www.w3.org/2005/Atom}"
_CONTENT = "{http://purl.org/rss/1.0/modules/content/}"
_DC = "{http://purl.org/dc/elements/1.1/}"


class FeedError(ValueError):
    """Raised when content cannot be interpreted as an RSS/Atom feed."""


def _txt(el) -> str:
    return (el.text or "").strip() if el is not None else ""


def _fallback_parse(content: bytes) -> dict[str, Any]:
    head = content[:4096].lower()
    if b"<!doctype" in head or b"<!entity" in head:
        raise FeedError("Feed rejected: DTD/entity declarations are not allowed")
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise FeedError(f"Invalid XML: {exc}") from exc

    entries: list[dict[str, Any]] = []
    tag = root.tag.lower()
    if tag.endswith("rss") or tag.endswith("rdf"):
        channel = root.find("channel") if root.find("channel") is not None else root
        feed_title = _txt(channel.find("title"))
        feed_link = _txt(channel.find("link"))
        for it in root.iter("item"):
            body = _txt(it.find(_CONTENT + "encoded")) or _txt(it.find("description"))
            entries.append({
                "id": _txt(it.find("guid")) or _txt(it.find("link")),
                "title": _txt(it.find("title")),
                "link": _txt(it.find("link")),
                "published": _txt(it.find("pubDate")) or _txt(it.find(_DC + "date")),
                "author": _txt(it.find("author")) or _txt(it.find(_DC + "creator")),
                "content": body,
                "tags": [_txt(c) for c in it.findall("category") if _txt(c)],
            })
    elif tag.endswith("feed"):
        feed_title = _txt(root.find(_ATOM + "title"))
        feed_link = ""
        for ln in root.findall(_ATOM + "link"):
            if ln.get("rel", "alternate") == "alternate":
                feed_link = ln.get("href", "")
                break
        for en in root.findall(_ATOM + "entry"):
            link = ""
            for ln in en.findall(_ATOM + "link"):
                if ln.get("rel", "alternate") == "alternate":
                    link = ln.get("href", "")
                    break
            author_el = en.find(_ATOM + "author")
            entries.append({
                "id": _txt(en.find(_ATOM + "id")) or link,
                "title": _txt(en.find(_ATOM + "title")),
                "link": link,
                "published": _txt(en.find(_ATOM + "published")) or _txt(en.find(_ATOM + "updated")),
                "author": _txt(author_el.find(_ATOM + "name")) if author_el is not None else "",
                "content": _txt(en.find(_ATOM + "content")) or _txt(en.find(_ATOM + "summary")),
                "tags": [c.get("term", "") for c in en.findall(_ATOM + "category") if c.get("term")],
            })
    else:
        raise FeedError("Document is not an RSS or Atom feed")
    return {"feed_title": feed_title, "feed_link": feed_link, "entries": entries}


def _feedparser_parse(content: bytes) -> dict[str, Any]:  # pragma: no cover
    feed = _fp.parse(content)
    if getattr(feed, "bozo", 0) and not feed.entries:      # feedparser is lenient: do not accept broken XML as an empty valid feed
        exc = getattr(feed, "bozo_exception", None)
        if not isinstance(exc, getattr(_fp, "CharacterEncodingOverride", ())):
            raise FeedError(f"Invalid XML: {exc}")
    if not feed.entries and not feed.feed.get("title"):
        raise FeedError("Document could not be parsed as an RSS/Atom feed")
    out = []
    for e in feed.entries:
        body = ""
        if e.get("content"):
            body = e.content[0].get("value", "")
        elif e.get("summary"):
            body = e.summary
        out.append({
            "id": e.get("id") or e.get("link", ""),
            "title": e.get("title", ""),
            "link": e.get("link", ""),
            "published": e.get("published") or e.get("updated") or e.get("created") or "",
            "author": e.get("author", ""),
            "content": body,
            "tags": [t.get("term", "") for t in e.get("tags", []) if t.get("term")],
        })
    return {"feed_title": feed.feed.get("title", ""), "feed_link": feed.feed.get("link", ""), "entries": out}


def parse_feed(content: bytes | str) -> dict[str, Any]:
    """Parse feed bytes into {feed_title, feed_link, entries[]}. Raises FeedError."""
    if isinstance(content, str):
        content = content.encode("utf-8")
    if not content or not content.strip():
        raise FeedError("Empty response")
    if re.match(rb"\s*<(!doctype html|html)", content[:200], re.I):
        raise FeedError("URL returned an HTML page, not an RSS/Atom feed")
    if _fp is not None:
        try:
            return _feedparser_parse(content)
        except FeedError:
            raise
        except Exception:  # fall through to stdlib parser
            pass
    return _fallback_parse(content)
