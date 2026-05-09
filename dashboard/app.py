#!/usr/bin/env python3
import json
import os
import re
import sys
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from flask import Flask, jsonify, render_template, request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import RAW_DATA_DIR

app = Flask(__name__)

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

# ── TTL cache ─────────────────────────────────────────────────────────────────
_CACHE_TTL = 60  # seconds
_cache: dict = {}
_cache_lock = threading.Lock()


def _cached(key: str, fn, ttl: int = _CACHE_TTL):
    with _cache_lock:
        entry = _cache.get(key)
        if entry and time.monotonic() - entry["ts"] < ttl:
            return entry["data"]
    data = fn()
    with _cache_lock:
        _cache[key] = {"data": data, "ts": time.monotonic()}
    return data


# ── Core loader (single source of truth) ─────────────────────────────────────

def _parse_ts(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def _load_recent(days: int = 7) -> list[dict]:
    cutoff = datetime.now() - timedelta(days=days)
    items: list[dict] = []
    seen_ids: set[str] = set()

    for platform in ("reddit", "github", "blog"):
        d = os.path.join(RAW_DATA_DIR, platform)
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d), reverse=True):
            if not fn.endswith(".jsonl"):
                continue
            try:
                with open(os.path.join(d, fn), encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            item = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        item_id = item.get("id") or item.get("url", "")
                        if item_id in seen_ids:
                            continue
                        seen_ids.add(item_id)
                        dt = _parse_ts(item.get("collected_at") or item.get("timestamp", ""))
                        if dt and dt.replace(tzinfo=None) > cutoff:
                            items.append(item)
            except OSError as e:
                app.logger.error("Error reading %s: %s", fn, e)
    return items


def _get_items() -> list[dict]:
    return _cached("all_items", _load_recent)


# ── Pagination helper ─────────────────────────────────────────────────────────

def _paginate(items: list, page: int, per_page: int) -> dict:
    per_page = min(per_page, 200)
    start = (page - 1) * per_page
    return {
        "items": items[start: start + per_page],
        "total": len(items),
        "page": page,
        "per_page": per_page,
        "pages": max(1, -(-len(items) // per_page)),  # ceiling division
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/stats")
def api_stats():
    def _build():
        items = _load_recent(days=7)
        now = datetime.now()
        cutoff_24h = now - timedelta(hours=24)
        by_platform = Counter(i.get("platform") for i in items)
        by_category = Counter(i.get("category", "uncategorized") for i in items)
        recent_24h = 0
        timeline = defaultdict(lambda: {"reddit": 0, "github": 0, "blog": 0})
        for item in items:
            dt = _parse_ts(item.get("collected_at", ""))
            if dt:
                if dt.replace(tzinfo=None) > cutoff_24h:
                    recent_24h += 1
                timeline[dt.strftime("%Y-%m-%d")][item.get("platform", "unknown")] += 1
        return {
            "total": len(items),
            "recent_24h": recent_24h,
            "by_platform": dict(by_platform),
            "by_category": dict(by_category),
            "timeline": dict(sorted(timeline.items())),
        }
    return jsonify(_cached("stats", _build))


@app.route("/api/feed/<platform>")
def api_feed(platform: str):
    if platform not in ("reddit", "github", "blog"):
        return jsonify({"error": "invalid platform"}), 400
    page = max(1, request.args.get("page", 1, type=int))
    per_page = request.args.get("per_page", 60, type=int)

    items = [i for i in _get_items() if i.get("platform") == platform]
    items.sort(key=lambda x: x.get("signal_score", 0), reverse=True)
    return jsonify(_paginate(items, page, per_page))


@app.route("/api/zerodays")
def api_zerodays():
    page = max(1, request.args.get("page", 1, type=int))
    per_page = request.args.get("per_page", 60, type=int)

    def _build():
        results = []
        for item in _load_recent(days=7):
            text = f"{item.get('title', '')} {item.get('text', '')[:500]}"
            if _CVE_RE.search(text):
                continue
            if item.get("signal_score", 0) >= 8:
                results.append(item)
        results.sort(key=lambda x: x.get("signal_score", 0), reverse=True)
        return results

    results = _cached("zerodays", _build)
    return jsonify(_paginate(results, page, per_page))


@app.route("/api/cves")
def api_cves():
    page = max(1, request.args.get("page", 1, type=int))
    per_page = request.args.get("per_page", 60, type=int)

    def _build():
        results = []
        for item in _load_recent(days=7):
            text = f"{item.get('title', '')} {item.get('text', '')[:500]}"
            cves = list(set(_CVE_RE.findall(text)))
            if not cves:
                continue
            if item.get("signal_score", 0) >= 6:
                item["cve_ids"] = cves[:5]
                results.append(item)
        results.sort(key=lambda x: x.get("signal_score", 0), reverse=True)
        return results

    results = _cached("cves", _build)
    return jsonify(_paginate(results, page, per_page))


@app.route("/api/search")
def api_search():
    q = request.args.get("q", "").lower().strip()
    if not (3 <= len(q) <= 200):
        return jsonify({"error": "query must be 3–200 characters"}), 400
    page = max(1, request.args.get("page", 1, type=int))
    per_page = request.args.get("per_page", 50, type=int)

    items = _get_items()
    results = [
        i for i in items
        if q in (i.get("title") or "").lower()
        or q in (i.get("text") or "").lower()
    ]
    results.sort(key=lambda x: x.get("signal_score", 0), reverse=True)
    return jsonify(_paginate(results, page, per_page))


if __name__ == "__main__":
    print("Dashboard running at http://localhost:5000")
    app.run(debug=False, host="0.0.0.0", port=5000)
