"""
REST API — exposes collected intel + trending CVEs for the frontend.
All responses are JSON. No HTML.
"""
import html
import re
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from flask import Flask, jsonify, request
from flask_cors import CORS

from pipeline.tracker import get_trending, get_all_mentions
from storage.db import load_recent_raw, load_verifications
from utils.audit  import get_recent as audit_recent, get_stats as audit_stats
from utils.logger import get_logger

app    = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "http://localhost:5173"}})
logger = get_logger("api")

_CVE_RE   = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
_HTML_TAG = re.compile(r"<[^>]+>")


def _strip_html(text: str) -> str:
    if not text or "<" not in text:
        return text
    text = _HTML_TAG.sub(" ", text)
    text = html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def _clean(item: dict) -> dict:
    """Strip HTML from text field before sending to frontend."""
    if item.get("text"):
        item["text"] = _strip_html(item["text"])
    return item

# ── TTL cache ─────────────────────────────────────────────────────────────────
_CACHE: dict = {}
_CACHE_LOCK  = threading.Lock()
_CACHE_TTL   = 60  # seconds


def _cached(key: str, fn, ttl: int = _CACHE_TTL):
    with _CACHE_LOCK:
        entry = _CACHE.get(key)
        if entry and time.monotonic() - entry["ts"] < ttl:
            return entry["data"]
    data = fn()
    with _CACHE_LOCK:
        _CACHE[key] = {"data": data, "ts": time.monotonic()}
    return data


def _paginate(items: list, page: int, per_page: int) -> dict:
    per_page = min(max(per_page, 1), 200)
    start    = (page - 1) * per_page
    return {
        "items":    items[start: start + per_page],
        "total":    len(items),
        "page":     page,
        "per_page": per_page,
        "pages":    max(1, -(-len(items) // per_page)),
    }


def _get_items(days: int = 7) -> list[dict]:
    return _cached(f"items_{days}", lambda: [_clean(i) for i in load_recent_raw(days=days)])


def _parse_ts(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "ts": datetime.utcnow().isoformat()})


@app.route("/api/stats")
def stats():
    def _build():
        items  = load_recent_raw(days=7)
        now    = datetime.now()
        c24h   = now - timedelta(hours=24)
        recent = sum(
            1 for i in items
            if (dt := _parse_ts(i.get("collected_at", ""))) and dt.replace(tzinfo=None) > c24h
        )
        timeline = defaultdict(lambda: {"reddit": 0, "github": 0, "blog": 0, "nvd": 0})
        for item in items:
            dt = _parse_ts(item.get("collected_at", ""))
            if dt:
                timeline[dt.strftime("%Y-%m-%d")][item.get("platform", "unknown")] += 1
        return {
            "total":       len(items),
            "recent_24h":  recent,
            "by_platform": dict(Counter(i.get("platform") for i in items)),
            "by_category": dict(Counter(i.get("category", "uncategorized") for i in items)),
            "timeline":    dict(sorted(timeline.items())),
        }
    return jsonify(_cached("stats", _build))


@app.route("/api/trending")
def trending():
    """CVEs trending by mention count — the core CVEPulse-style endpoint."""
    hours = request.args.get("hours", 24, type=int)
    top   = request.args.get("top", 20, type=int)
    return jsonify(get_trending(hours=hours, top_n=top))


@app.route("/api/trending/<cve_id>")
def trending_detail(cve_id: str):
    """All recorded mentions for a specific CVE."""
    return jsonify({
        "cve_id":   cve_id.upper(),
        "mentions": get_all_mentions(cve_id),
    })


@app.route("/api/feed/<platform>")
def feed(platform: str):
    if platform not in ("reddit", "github", "blog", "nvd", "all"):
        return jsonify({"error": "invalid platform"}), 400
    page      = max(1, request.args.get("page", 1, type=int))
    per_page  = request.args.get("per_page", 50, type=int)
    days      = request.args.get("days", 7, type=int)
    items     = _get_items(days)
    if platform != "all":
        items = [i for i in items if i.get("platform") == platform]
    items.sort(key=lambda x: x.get("signal_score", 0), reverse=True)
    return jsonify(_paginate(items, page, per_page))


@app.route("/api/zerodays")
def zerodays():
    page      = max(1, request.args.get("page", 1, type=int))
    per_page  = request.args.get("per_page", 50, type=int)
    days      = request.args.get("days", 7, type=int)
    min_score = request.args.get("min_score", 8, type=int)

    def _build():
        results = []
        for item in load_recent_raw(days=days):
            text = f"{item.get('title', '')} {item.get('text', '')[:500]}"
            if _CVE_RE.search(text):
                continue
            if item.get("signal_score", 0) >= min_score:
                results.append(item)
        results.sort(key=lambda x: x.get("signal_score", 0), reverse=True)
        return results

    return jsonify(_paginate(_cached(f"zerodays_{days}_{min_score}", _build), page, per_page))


@app.route("/api/cves")
def cves():
    page      = max(1, request.args.get("page", 1, type=int))
    per_page  = request.args.get("per_page", 50, type=int)
    days      = request.args.get("days", 7, type=int)
    min_score = request.args.get("min_score", 6, type=int)

    def _build():
        results = []
        for item in load_recent_raw(days=days):
            text     = f"{item.get('title', '')} {item.get('text', '')[:500]}"
            cve_list = list(set(_CVE_RE.findall(text)))
            if not cve_list:
                continue
            if item.get("signal_score", 0) >= min_score:
                item["cve_ids"] = cve_list[:5]
                results.append(item)
        results.sort(key=lambda x: x.get("signal_score", 0), reverse=True)
        return results

    return jsonify(_paginate(_cached(f"cves_{days}_{min_score}", _build), page, per_page))


@app.route("/api/search")
def search():
    q = request.args.get("q", "").lower().strip()
    if not (3 <= len(q) <= 200):
        return jsonify({"error": "query must be 3-200 characters"}), 400
    page     = max(1, request.args.get("page", 1, type=int))
    per_page = request.args.get("per_page", 50, type=int)
    days     = request.args.get("days", 7, type=int)
    items    = _get_items(days)
    results  = [
        i for i in items
        if q in (i.get("title") or "").lower()
        or q in (i.get("text") or "").lower()
    ]
    results.sort(key=lambda x: x.get("signal_score", 0), reverse=True)
    return jsonify(_paginate(results, page, per_page))


@app.route("/api/audit")
def audit_log():
    """Last N audit entries — full system activity trail."""
    n = request.args.get("n", 100, type=int)
    return jsonify(audit_recent(min(n, 500)))


@app.route("/api/audit/stats")
def audit_stats_endpoint():
    """Aggregate counters: items collected, passed, dropped, notifications, errors."""
    return jsonify(audit_stats())


@app.route("/api/item/<item_id>")
def item_detail(item_id: str):
    for item in _get_items(days=30):
        if item.get("id") == item_id:
            return jsonify(item)
    return jsonify({"error": "not found"}), 404


@app.route("/api/verified")
def verified():
    """Phase 3 verification results — confirmed/likely/unverified items."""
    days      = request.args.get("days", 7, type=int)
    status    = request.args.get("status", "")   # confirmed | likely | unverified
    page      = max(1, request.args.get("page", 1, type=int))
    per_page  = request.args.get("per_page", 50, type=int)

    def _build():
        results = load_verifications(days=days)
        if status:
            results = [r for r in results if r.get("verification_status") == status]
        return results

    return jsonify(_paginate(_cached(f"verified_{days}_{status}", _build), page, per_page))


@app.route("/api/verified/<raw_id>")
def verified_detail(raw_id: str):
    """Verification record for a specific raw item."""
    results = load_verifications(days=30)
    for r in results:
        if r.get("raw_id") == raw_id:
            return jsonify(r)
    return jsonify({"error": "not found"}), 404


def run(host: str = "0.0.0.0", port: int = 8000, debug: bool = False) -> None:
    logger.info("API server starting on %s:%d", host, port)
    app.run(host=host, port=port, debug=debug)
