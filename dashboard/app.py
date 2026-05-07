#!/usr/bin/env python3
import json
import os
import sys
import re
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from flask import Flask, render_template, jsonify, request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import RAW_DATA_DIR

app = Flask(__name__)

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def _parse_ts(ts):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except:
        return None


def load_recent(days=7):
    cutoff = datetime.now() - timedelta(days=days)
    items = []
    for platform in ["reddit", "github", "blog"]:
        d = os.path.join(RAW_DATA_DIR, platform)
        if not os.path.exists(d):
            continue
        for fn in os.listdir(d):
            if not fn.endswith(".jsonl"):
                continue
            try:
                with open(os.path.join(d, fn), encoding="utf-8") as f:
                    for line in f:
                        if not line.strip():
                            continue
                        item = json.loads(line)
                        dt = _parse_ts(item.get("collected_at") or item.get("timestamp", ""))
                        if dt and dt.replace(tzinfo=None) > cutoff:
                            items.append(item)
            except Exception as e:
                print(f"Error: {e}")
    return items


def dedupe(items, key="url"):
    seen = set()
    out = []
    for item in items:
        v = item.get(key, "")
        if v and v in seen:
            continue
        seen.add(v)
        out.append(item)
    return out


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/stats")
def api_stats():
    items = load_recent(days=7)
    now = datetime.now()
    cutoff_24h = now - timedelta(hours=24)

    by_platform = Counter(i.get("platform") for i in items)
    by_category = Counter(i.get("category", "uncategorized") for i in items)
    recent_24h  = 0
    timeline    = defaultdict(lambda: {"reddit": 0, "github": 0, "blog": 0})

    for item in items:
        dt = _parse_ts(item.get("collected_at", ""))
        if dt:
            if dt.replace(tzinfo=None) > cutoff_24h:
                recent_24h += 1
            timeline[dt.strftime("%Y-%m-%d")][item.get("platform", "unknown")] += 1

    return jsonify({
        "total":       len(items),
        "recent_24h":  recent_24h,
        "by_platform": by_platform,
        "by_category": by_category,
        "timeline":    dict(sorted(timeline.items())),
    })


@app.route("/api/feed/<platform>")
def api_feed(platform):
    items = load_recent(days=7)
    filtered = [i for i in items if i.get("platform") == platform]
    filtered.sort(key=lambda x: x.get("signal_score", 0), reverse=True)
    return jsonify(dedupe(filtered)[:60])


@app.route("/api/zerodays")
def api_zerodays():
    """Zero-day candidates: high signal score, no CVE ID."""
    items = load_recent(days=7)
    results = []
    for item in items:
        text = f"{item.get('title','')} {item.get('text','')[:500]}"
        if _CVE_RE.search(text):
            continue
        score = item.get("signal_score", 0)
        if score >= 8:
            results.append(item)
    results.sort(key=lambda x: x.get("signal_score", 0), reverse=True)
    return jsonify(dedupe(results)[:60])


@app.route("/api/cves")
def api_cves():
    """CVE-tagged vulnerabilities actively discussed."""
    items = load_recent(days=7)
    results = []
    for item in items:
        text = f"{item.get('title','')} {item.get('text','')[:500]}"
        cves = list(set(_CVE_RE.findall(text)))
        if not cves:
            continue
        if item.get("signal_score", 0) >= 6:
            item["cve_ids"] = cves[:3]
            results.append(item)
    results.sort(key=lambda x: x.get("signal_score", 0), reverse=True)
    return jsonify(dedupe(results)[:60])


@app.route("/api/search")
def api_search():
    q = request.args.get("q", "").lower().strip()
    if len(q) < 3:
        return jsonify([])
    items = load_recent(days=7)
    results = [i for i in items
               if q in (i.get("title") or "").lower()
               or q in (i.get("text") or "").lower()]
    results.sort(key=lambda x: x.get("signal_score", 0), reverse=True)
    return jsonify(dedupe(results)[:100])


if __name__ == "__main__":
    print("Dashboard running at http://localhost:5000")
    app.run(debug=False, host="0.0.0.0", port=5000)
