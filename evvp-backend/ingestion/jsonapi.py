"""Generic JSON-API / "custom" source adapter (report: source Type 1 and Type 3).

An analyst describes where the fields live in the JSON with a *mapping* (dotted paths), so a new API source needs no code:

    {"items_path": "data.advisories", "id_field": "advisory_id", "title_field": "name",
     "url_field": "link", "date_field": "issued", "text_field": "summary"}

Only ``title_field`` is required. ``items_path`` may be empty when the response is a top-level list.
Output has the same shape as ingestion.feedparse.parse_feed(), so the normal pipeline handles it unchanged.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from ingestion.feedparse import FeedError

MAPPING_KEYS = ("items_path", "id_field", "title_field", "url_field", "date_field", "text_field")
_PATH_RE = re.compile(r"^[A-Za-z0-9_\-]+(\.[A-Za-z0-9_\-]+)*$")
MAX_ENTRIES = 500


def clean_mapping(mapping) -> dict:
    """Validate a mapping from user input. Raises ValueError with a readable message."""
    if not isinstance(mapping, dict):
        raise ValueError("API/custom sources need a field mapping (at least title_field)")
    unknown = set(mapping) - set(MAPPING_KEYS)
    if unknown:
        raise ValueError(f"unknown mapping key(s): {', '.join(sorted(unknown))}")
    out = {}
    for k in MAPPING_KEYS:
        v = mapping.get(k)
        if v in (None, ""):
            continue
        if not isinstance(v, str) or len(v) > 100 or not _PATH_RE.match(v.strip()):
            raise ValueError(f"{k} must be a dotted field path such as 'data.items' (letters, digits, _ - and dots)")
        out[k] = v.strip()
    if "title_field" not in out:
        raise ValueError("mapping.title_field is required")
    return out


def _get(obj, path: str | None):
    if not path:
        return obj
    for part in path.split("."):
        if isinstance(obj, dict):
            obj = obj.get(part)
        elif isinstance(obj, list) and part.isdigit() and int(part) < len(obj):
            obj = obj[int(part)]
        else:
            return None
    return obj


def _text(v) -> str:
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False)[:2000]
    return str(v).strip()


def _date(v) -> str:
    if isinstance(v, (int, float)) and v > 0:
        try:                                              # epoch seconds (or milliseconds)
            return datetime.fromtimestamp(v / 1000 if v > 1e11 else v, tz=timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            return ""
    return _text(v)


def parse_json_feed(content: bytes, mapping: dict, name: str = "", url: str = "") -> dict:
    try:
        data = json.loads(content.decode("utf-8", errors="replace"))
    except ValueError:
        raise FeedError("The response is not valid JSON")
    m = clean_mapping(mapping)
    items = _get(data, m.get("items_path"))
    if not isinstance(items, list):
        raise FeedError(f"items_path '{m.get('items_path', '')}' does not point to a list in the response")
    entries = []
    for it in items[:MAX_ENTRIES]:
        if not isinstance(it, dict):
            continue
        title = _text(_get(it, m["title_field"]))
        if not title:
            continue
        link = _text(_get(it, m.get("url_field")))
        entries.append({
            "id": _text(_get(it, m.get("id_field"))) or link or title,
            "title": title, "link": link if link.startswith(("http://", "https://")) else "",
            "published": _date(_get(it, m.get("date_field"))), "content": _text(_get(it, m.get("text_field")))[:5000],
            "author": "", "tags": [],
        })
    return {"feed_title": name, "feed_link": url, "entries": entries}
