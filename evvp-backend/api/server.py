"""EVVP REST API + dashboard host.

All responses are JSON under /api; the analyst dashboard (web/) is served at "/".
Read endpoints are open; write endpoints (POST/PATCH/DELETE) require
``Authorization: Bearer <EVVP_API_TOKEN>`` when that environment variable is set.
"""
from __future__ import annotations

import hmac
import os
import re
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from flask import Flask, jsonify, request, send_from_directory

from config.settings import API_CACHE_TTL, API_TOKEN_ENV, CORS_ORIGINS, HIGH_RISK_THRESHOLD, ZERO_DAY_MIN_SCORE
from pipeline.entities import build_cve_records, build_entities, save_snapshot
from pipeline.tracker import get_all_mentions
from source_manager import manager as sources
from source_manager.routes import sources_bp
from storage import analyst as analyst_store
from storage import db
from utils.audit import get_recent as audit_recent
from utils.logger import get_logger
from utils.timeutil import iso, parse_ts

logger = get_logger("api")
WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")

app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024
app.config["JSON_SORT_KEYS"] = False
app.register_blueprint(sources_bp)

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class ApiError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message, self.status = message, status


# ── security: CORS, token, headers ────────────────────────────────────────────
def _cors(resp, origin):
    if origin and origin in CORS_ORIGINS:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Vary"] = "Origin"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PATCH, DELETE, OPTIONS"
    return resp


@app.before_request
def _guard():
    if request.method == "OPTIONS":
        return _cors(app.make_response(("", 204)), request.headers.get("Origin"))
    token = os.getenv(API_TOKEN_ENV, "")
    if token and request.path.startswith("/api/") and request.method in _WRITE_METHODS:
        supplied = request.headers.get("Authorization", "")
        if not hmac.compare_digest(supplied.encode(), f"Bearer {token}".encode()):
            return jsonify({"error": "Unauthorized — a valid API token is required for changes"}), 401
    return None


@app.after_request
def _headers(resp):
    _cors(resp, request.headers.get("Origin"))
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    else:
        resp.headers.setdefault("Content-Security-Policy",
                                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
    return resp


@app.errorhandler(ApiError)
def _api_error(e):
    return jsonify({"error": e.message}), e.status


@app.errorhandler(404)
def _404(e):
    return jsonify({"error": "not found"}), 404


@app.errorhandler(405)
def _405(e):
    return jsonify({"error": "method not allowed"}), 405


@app.errorhandler(413)
def _413(e):
    return jsonify({"error": "request body too large (max 1 MB)"}), 413


@app.errorhandler(db.StorageError)
def _storage_error(e):
    logger.error("Storage unavailable on %s %s: %s", request.method, request.path, e)
    return jsonify({"error": f"storage unavailable: {e}", "storage_error": True}), 503


@app.errorhandler(Exception)
def _500(e):
    logger.exception("Unhandled error on %s %s", request.method, request.path)
    return jsonify({"error": "internal server error"}), 500


# ── data snapshot (entities are rebuilt only when data changes or the TTL passes) ──
_lock = threading.Lock()
_snap: dict = {}


def invalidate() -> None:
    with _lock:
        _snap.clear()


def _snapshot() -> dict:
    with _lock:
        if _snap and _snap["version"] == db.DATA_VERSION and time.monotonic() - _snap["ts"] < API_CACHE_TTL:
            return _snap
    items = db.load_recent_raw(days=0)
    verifs = db.load_verifications(days=0)
    entities = build_entities(items, verifs, analyst_store.latest_by_entity())
    cves = build_cve_records(entities, items)
    snap = {"version": db.DATA_VERSION, "ts": time.monotonic(), "items": items, "entities": entities,
            "by_id": {e["id"]: e for e in entities}, "cves": cves, "cve_by_id": {c["cve_id"]: c for c in cves}}
    with _lock:
        _snap.clear()
        _snap.update(snap)
    save_snapshot(entities)
    return snap


# ── request helpers ───────────────────────────────────────────────────────────
def _int(name: str, default: int, lo: int | None = None, hi: int | None = None) -> int:
    raw = request.args.get(name)
    if raw in (None, ""):
        return default
    try:
        v = int(raw)
    except ValueError:
        raise ApiError(f"{name} must be a whole number")
    if (lo is not None and v < lo) or (hi is not None and v > hi):
        raise ApiError(f"{name} must be between {lo} and {hi}")
    return v


def _bool(name: str) -> bool | None:
    raw = (request.args.get(name) or "").lower()
    if raw == "":
        return None
    if raw in ("true", "1", "yes"):
        return True
    if raw in ("false", "0", "no"):
        return False
    raise ApiError(f"{name} must be true or false")


def _order() -> bool:
    o = (request.args.get("order") or "desc").lower()
    if o not in ("asc", "desc"):
        raise ApiError("order must be asc or desc")
    return o == "desc"


def _paginate(items: list, per_default: int = 50) -> dict:
    per_page = _int("per_page", per_default, 1, 200)
    pages = max(1, -(-len(items) // per_page))
    page = min(_int("page", 1, 1), pages)                     # out-of-range pages clamp to the last page
    start = (page - 1) * per_page
    return {"items": items[start:start + per_page], "total": len(items), "page": page, "per_page": per_page, "pages": pages}


def _within_days(e: dict, days: int, key: str = "last_updated") -> bool:
    if days <= 0:
        return True
    ts = parse_ts(e.get(key))
    return bool(ts and ts >= datetime.now(timezone.utc) - timedelta(days=days))


def _slim(e: dict) -> dict:
    """List view: omit the heavy evidence/timeline blocks (use the detail endpoint for those)."""
    out = {k: v for k, v in e.items() if k not in ("evidence", "timeline", "references", "risk_reasons")}
    out["description"] = (e.get("description") or "")[:300]
    return out


def _real(entities: list[dict]) -> list[dict]:
    return [e for e in entities if not e["roundup"]]


_SORT = {
    "risk": lambda e: e["risk_score"], "first_seen": lambda e: e.get("first_seen") or "",
    "last_updated": lambda e: e.get("last_updated") or "", "mentions": lambda e: e["mentions"],
    "sources": lambda e: e["cross_source_count"], "cvss": lambda e: e.get("cvss") or 0,
    "epss": lambda e: e.get("epss") or 0, "trend": lambda e: e["trend"]["score"],
    "zero_day": lambda e: e["zero_day_score"],
}


# ── health & stats ────────────────────────────────────────────────────────────
def _source_summary() -> dict:
    srcs = sources.list_sources()
    return {"total": len(srcs), "enabled": sum(1 for s in srcs if s["enabled"]),
            "failing": sum(1 for s in srcs if s["enabled"] and s["status"] == "error")}


@app.route("/api/health")
def health():
    """200 when the configured storage works; 503 + the reason when it does not (never a silent fallback)."""
    ts = datetime.now(timezone.utc).isoformat()
    try:
        backend = db.check_storage()
        snap = _snapshot()
    except db.StorageError as exc:
        configured = "postgresql" if db.DB_URL else "jsonl"
        return jsonify({"status": "degraded", "ts": ts, "storage": configured, "storage_error": str(exc), "sources": _source_summary()}), 503
    return jsonify({"status": "ok", "ts": ts, "storage": backend, "findings": len(_real(snap["entities"])),
                    "items": len(snap["items"]), "sources": _source_summary()})


@app.route("/api/stats")
def stats():
    snap = _snapshot()
    ents, items = _real(snap["entities"]), snap["items"]
    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(hours=24)

    def first_collected(e):
        return parse_ts(e.get("first_collected") or e.get("first_seen"))

    sev = Counter(e["severity"] for e in ents)
    cat, tech = Counter(), Counter()
    for e in ents:
        for t in (e["vuln_types"] or ["Other"]):
            cat[t] += 1
        for t in e["attack_techniques"]:
            tech[f"{t['id']} {t['name']}"] += 1
    by_day = defaultdict(lambda: {"findings": 0, "risk": 0})
    for e in ents:
        d = (e.get("first_seen") or "")[:10]
        if d:
            by_day[d]["findings"] += 1
            by_day[d]["risk"] += e["risk_score"]
    fot = [{"date": d, "findings": v["findings"], "avg_risk": round(v["risk"] / v["findings"], 1)} for d, v in sorted(by_day.items())]
    src_day = defaultdict(Counter)
    for it in items:                       # count every piece of evidence: the primary item plus reports folded in as evidence
        d = (iso(parse_ts(it.get("collected_at"))) or "")[:10]
        if d:
            src_day[d][it.get("platform", "unknown")] += 1
        for x in it.get("sources") or []:
            if x.get("url") and x.get("url") != it.get("url"):
                xd = (iso(parse_ts(x.get("collected_at") or it.get("collected_at"))) or d or "")[:10]
                if xd:
                    src_day[xd][x.get("platform", "unknown")] += 1
    sot = [{"date": d, **dict(c)} for d, c in sorted(src_day.items())]
    stamps = [t for t in (parse_ts(i.get("collected_at")) for i in items) if t]
    return jsonify({
        "total": len(ents), "total_findings": len(ents), "total_evidence_items": len(items),
        "new_findings": sum(1 for e in ents if (fc := first_collected(e)) and fc >= day_ago),
        "high_risk": sum(1 for e in ents if e["risk_score"] >= HIGH_RISK_THRESHOLD),
        "critical_cves": sum(1 for c in snap["cves"] if c["severity"] == "CRITICAL"),
        "potential_zero_days": sum(1 for e in ents if e["zero_day_candidate"]),
        "active_exploitation": sum(1 for e in ents if e["active_exploitation"]),
        "multi_source": sum(1 for e in ents if e["cross_source_count"] >= 2),
        "early_detections": sum(1 for e in ents if e["lead_time"]["status"] == "early"),
        "sources": _source_summary(), "thresholds": {"high_risk": HIGH_RISK_THRESHOLD, "zero_day": ZERO_DAY_MIN_SCORE},
        "severity": {k: sev.get(k, 0) for k in SEVERITIES},
        "by_category": dict(cat.most_common()), "attack_techniques": dict(tech.most_common(10)),
        "by_platform": dict(Counter(i.get("platform", "unknown") for i in items)),
        "findings_over_time": fot, "sources_over_time": sot,
        "recent_24h": sum(1 for i in items if (t := parse_ts(i.get("collected_at"))) and t >= day_ago),
        "timeline": {r["date"]: {k: v for k, v in r.items() if k != "date"} for r in sot},     # React client shape
        "last_collected": iso(max(stamps)) if stamps else None,
    })


# ── findings (vulnerability entities) ─────────────────────────────────────────
@app.route("/api/vulns")
def vulns():
    ents = list(snap_entities := _snapshot()["entities"])
    if not (_bool("include_roundups") or False):
        ents = _real(ents)
    q = (request.args.get("q") or "").strip().lower()
    if q:
        ents = [e for e in ents if q in " ".join([e["title"], e["description"], " ".join(e["cve_ids"]), " ".join(e["affected_products"]),
                                                  " ".join(e["sources"]), " ".join(e["vuln_types"])]).lower()]
    sev = (request.args.get("severity") or "").upper()
    if sev:
        if sev not in SEVERITIES:
            raise ApiError(f"severity must be one of: {', '.join(SEVERITIES)}")
        ents = [e for e in ents if e["severity"] == sev]
    min_risk = _int("min_risk", 0, 0, 100)
    ents = [e for e in ents if e["risk_score"] >= min_risk]
    if src := (request.args.get("source") or "").strip().lower():
        ents = [e for e in ents if any(src in s.lower() for s in e["sources"])]
    if plat := (request.args.get("platform") or "").strip().lower():
        ents = [e for e in ents if plat in e["platforms"]]
    if status := (request.args.get("status") or "").strip():
        if status not in analyst_store.STATUSES:
            raise ApiError(f"status must be one of: {', '.join(analyst_store.STATUSES)}")
        ents = [e for e in ents if e["analyst"]["status"] == status]
    if cve := (request.args.get("cve") or "").strip().upper():
        ents = [e for e in ents if any(cve in c for c in e["cve_ids"])]
    if typ := (request.args.get("type") or "").strip().lower():
        ents = [e for e in ents if any(typ in t.lower() for t in e["vuln_types"])]
    for name, key in (("zero_day", "zero_day_candidate"), ("poc", "poc"), ("active", "active_exploitation"), ("has_cve", "has_cve")):
        flag = _bool(name)
        if flag is not None:
            ents = [e for e in ents if bool(e[key]) == flag]
    days = _int("days", 0, 0, 3650)
    ents = [e for e in ents if _within_days(e, days)]
    sort = request.args.get("sort") or "risk"
    if sort not in _SORT:
        raise ApiError(f"sort must be one of: {', '.join(_SORT)}")
    ents.sort(key=_SORT[sort], reverse=_order())
    page = _paginate(ents, 50)
    page["items"] = [_slim(e) for e in page["items"]]
    return jsonify(page)


def _entity(eid: str) -> dict:
    e = _snapshot()["by_id"].get(eid)
    if not e:
        raise ApiError("finding not found", 404)
    return e


@app.route("/api/vulns/<eid>")
def vuln_detail(eid: str):
    e = _entity(eid)
    return jsonify({**e, "analyst_history": analyst_store.history(e)})


def _decision(eid: str, kind: str):
    e = _entity(eid)                                      # 404 before validation
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ApiError("request body must be a JSON object")
    try:
        ev = analyst_store.record(e, data.get("status"), data.get("analyst"), data.get("notes"), kind=kind)
    except ValueError as exc:
        raise ApiError(str(exc))
    invalidate()
    return jsonify(ev), 201


@app.route("/api/vulns/<eid>/review", methods=["POST"])
def vuln_review(eid: str):
    return _decision(eid, "decision")


@app.route("/api/vulns/<eid>/notes", methods=["POST"])
def vuln_note(eid: str):
    return _decision(eid, "note")


# ── zero-days ─────────────────────────────────────────────────────────────────
@app.route("/api/zerodays")
def zerodays():
    min_score = _int("min_score", ZERO_DAY_MIN_SCORE, 0, 100)
    days = _int("days", 0, 0, 3650)
    ents = [e for e in _real(_snapshot()["entities"]) if e["zero_day_candidate"] and e["zero_day_score"] >= min_score
            and e["analyst"]["status"] != "false_positive" and _within_days(e, days)]
    ents.sort(key=lambda e: (e["zero_day_score"], e["risk_score"]), reverse=True)
    page = _paginate(ents, 20)
    page["items"] = [_slim(e) for e in page["items"]]
    return jsonify(page)


# ── CVEs ──────────────────────────────────────────────────────────────────────
_CVE_SORT = {"risk": lambda c: c["risk_score"], "cvss": lambda c: c.get("cvss") or 0, "epss": lambda c: c.get("epss") or 0,
             "first_seen": lambda c: c.get("first_seen") or "", "published": lambda c: c.get("published") or "",
             "sources": lambda c: c["cross_source_count"]}


@app.route("/api/cves")
def cves():
    rows = list(_snapshot()["cves"])
    q = (request.args.get("q") or "").strip().lower()
    if q:
        rows = [c for c in rows if q in f"{c['cve_id']} {c['description']} {c['title']} {' '.join(c['affected_products'])}".lower()]
    sev = (request.args.get("severity") or "").upper()
    if sev:
        if sev not in SEVERITIES:
            raise ApiError(f"severity must be one of: {', '.join(SEVERITIES)}")
        rows = [c for c in rows if c["severity"] == sev]
    nvd = _bool("nvd")
    if nvd is not None:
        rows = [c for c in rows if c["nvd_available"] == nvd]
    min_risk = _int("min_risk", 0, 0, 100)
    rows = [c for c in rows if c["risk_score"] >= min_risk]
    sort = request.args.get("sort") or "risk"
    if sort not in _CVE_SORT:
        raise ApiError(f"sort must be one of: {', '.join(_CVE_SORT)}")
    rows.sort(key=_CVE_SORT[sort], reverse=_order())
    page = _paginate(rows, 50)
    page["items"] = [{k: v for k, v in c.items() if k not in ("timeline", "references")} for c in page["items"]]
    return jsonify(page)


@app.route("/api/cves/<cve_id>")
def cve_detail(cve_id: str):
    if not _CVE_ID.match(cve_id):
        raise ApiError("not a valid CVE identifier (expected CVE-YYYY-NNNN)")
    rec = _snapshot()["cve_by_id"].get(cve_id.upper())
    if not rec:
        raise ApiError("CVE not found in collected intelligence", 404)
    return jsonify(rec)


# ── trending ──────────────────────────────────────────────────────────────────
@app.route("/api/trending")
def trending():
    hours = _int("hours", 24, 0, 24 * 365)
    top = _int("top", 20, 1, 100)
    ents = [e for e in _real(_snapshot()["entities"]) if e["analyst"]["status"] != "false_positive"]
    if hours:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        ents = [e for e in ents if (t := parse_ts(e.get("last_updated"))) and t >= cutoff]
    ents.sort(key=lambda e: e["trend"]["score"], reverse=True)
    return jsonify([{
        "entity_id": e["id"], "cve_id": e["primary_cve"], "title": e["title"], "mentions": e["mentions"], "mention_count": e["mentions"],
        "source_count": e["cross_source_count"], "sources": e["sources"], "risk_score": e["risk_score"], "severity": e["severity"],
        "trend": e["trend"], "zero_day_candidate": e["zero_day_candidate"], "active_exploitation": e["active_exploitation"],
        "latest": {"ts": e.get("last_updated"), "platform": (e["platforms"] or [""])[0], "url": "", "title": e["title"]},
    } for e in ents[:top]])


@app.route("/api/trending/<cve_id>")
def trending_detail(cve_id: str):
    if not _CVE_ID.match(cve_id):
        raise ApiError("not a valid CVE identifier")
    return jsonify({"cve_id": cve_id.upper(), "mentions": get_all_mentions(cve_id)})


# ── threat landscape ──────────────────────────────────────────────────────────
@app.route("/api/threat-landscape")
def threat_landscape():
    days = _int("days", 0, 0, 3650)
    ents = [e for e in _real(_snapshot()["entities"]) if _within_days(e, days)]
    n = len(ents)
    sev = Counter(e["severity"] for e in ents)
    cat, cat_risk, tech, srcs = Counter(), defaultdict(list), Counter(), Counter()
    for e in ents:
        for t in (e["vuln_types"] or ["Other"]):
            cat[t] += 1
            cat_risk[t].append(e["risk_score"])
        for t in e["attack_techniques"]:
            tech[f"{t['id']} {t['name']}"] += 1
        for s in e["sources"]:
            srcs[s] += 1
    by_platform = Counter(p for e in ents for p in e["platforms"])
    return jsonify({
        "days": days, "total": n, "critical": sev["CRITICAL"], "high": sev["HIGH"], "medium": sev["MEDIUM"], "low": sev["LOW"],
        "zero_day_candidates": sum(1 for e in ents if e["zero_day_candidate"]),
        "active_exploitation": sum(1 for e in ents if e["active_exploitation"]),
        "average_risk": round(sum(e["risk_score"] for e in ents) / n, 1) if n else 0,
        "by_platform": dict(by_platform), "by_category": dict(cat.most_common()),
        "categories": [{"name": k, "count": v, "share": round(v / n * 100, 1)} for k, v in cat.most_common(8)] if n else [],
        "high_risk_categories": sorted([{"name": k, "avg_risk": round(sum(v) / len(v), 1), "count": len(v)} for k, v in cat_risk.items()],
                                       key=lambda x: x["avg_risk"], reverse=True)[:8],
        "attack_techniques": [{"name": k, "count": v} for k, v in tech.most_common(10)],
        "top_sources": [{"name": k, "count": v} for k, v in srcs.most_common(10)],
        "trending": [_slim(e) for e in sorted(ents, key=lambda e: e["trend"]["score"], reverse=True)[:6]],
        "top_risk_items": [_slim(e) for e in sorted(ents, key=lambda e: e["risk_score"], reverse=True)[:10]],
    })


# ── audit ─────────────────────────────────────────────────────────────────────
@app.route("/api/audit")
def audit_log():
    n = _int("n", 100, 1, 1000)
    return jsonify(audit_recent(n, event=request.args.get("event") or None, q=request.args.get("q") or None))


@app.route("/api/audit/stats")
def audit_stats_endpoint():
    """Counts come from the persisted audit log (last 5000 events), so they are right in API-only mode too."""
    c = Counter(e.get("event") for e in audit_recent(5000))
    return jsonify({"items_collected": c["item_collected"], "items_passed": c["item_passed"], "items_dropped": c["item_dropped"],
                    "notifications": c["notification_sent"], "trending_alerts": c["trending_detected"],
                    "errors": c["error"] + c["worker_error"] + c["source_fetch_fail"] + c["nvd_fetch_fail"], "window": "last 5000 events"})


# ── legacy evidence-level endpoints (kept for the React app and older clients) ──
def _clean_text(item: dict) -> dict:
    t = item.get("text")
    if t and "<" in t:
        item = {**item, "text": re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", t)).strip()}
    return item


def _items(days: int) -> list[dict]:
    items = _snapshot()["items"]
    if days > 0:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        items = [i for i in items if (t := parse_ts(i.get("collected_at")) or parse_ts(i.get("timestamp"))) and t >= cutoff]
    return [_clean_text(i) for i in items]


def _evidence_rows(items: list[dict]) -> list[dict]:
    """Per-platform feeds list *every* report: stored items plus reports folded into a finding as evidence
    (a GitHub PoC or Reddit thread about a vulnerability already tracked is stored as evidence, not as a separate record)."""
    rows = list(items)
    for it in items:
        for n, x in enumerate(it.get("sources") or []):
            if not x.get("url") or x.get("url") == it.get("url"):
                continue
            rows.append({**{k: it.get(k) for k in ("signal_score", "category", "matched_signals", "cve_ids", "intelligence", "cross_source_count", "source_trust")},
                         "id": f"{it.get('id')}#evidence-{n}", "parent_id": it.get("id"), "evidence": True, "platform": x.get("platform", "unknown"),
                         "source": x.get("source") or x.get("platform"), "title": x.get("title") or it.get("title"), "url": x["url"],
                         "timestamp": x.get("observed_at") or "", "collected_at": x.get("collected_at") or it.get("collected_at"), "text": ""})
    return rows


@app.route("/api/feed/<platform>")
def feed(platform: str):
    if platform not in ("reddit", "github", "blog", "nvd", "cisa", "all"):
        raise ApiError("invalid platform (reddit, github, blog, nvd, cisa or all)")
    items = _evidence_rows(_items(_int("days", 0, 0, 3650)))
    if platform != "all":
        items = [i for i in items if i.get("platform") == platform]
    items.sort(key=lambda x: x.get("signal_score", 0), reverse=True)
    return jsonify(_paginate(items, 50))


@app.route("/api/search")
def search():
    q = (request.args.get("q") or "").lower().strip()
    if not 3 <= len(q) <= 200:
        raise ApiError("query must be 3-200 characters")
    res = [i for i in _items(_int("days", 0, 0, 3650)) if q in (i.get("title") or "").lower() or q in (i.get("text") or "").lower()]
    res.sort(key=lambda x: x.get("signal_score", 0), reverse=True)
    return jsonify(_paginate(res, 50))


@app.route("/api/item/<item_id>")
def item_detail(item_id: str):
    for it in _snapshot()["items"]:
        if it.get("id") == item_id:
            return jsonify(_clean_text(it))
    raise ApiError("not found", 404)


@app.route("/api/evidence/<item_id>")
def evidence(item_id: str):
    for item in _snapshot()["items"]:
        if item.get("id") == item_id:
            intel = item.get("intelligence") or {}
            return jsonify({
                "item_id": item_id, "title": item.get("title"), "cve_ids": item.get("cve_ids", []),
                "risk_score": intel.get("risk_score", 0), "risk_reasons": intel.get("risk_reasons", []),
                "risk_breakdown": intel.get("risk_breakdown", []),
                "zero_day_score": intel.get("zero_day_score", 0), "zero_day_evidence": intel.get("zero_day_evidence", []),
                "cross_source_count": item.get("cross_source_count", 1),
                "sources": item.get("sources", [{"url": item.get("url", ""), "platform": item.get("platform", "unknown")}]),
                "attack_techniques": intel.get("attack_techniques", []),
                "nvd_data": item.get("nvd_data", []), "epss_data": item.get("epss_data", []),
            })
    raise ApiError("not found", 404)


@app.route("/api/analyst")
def analyst_search():
    q = (request.args.get("q") or "").strip().lower()
    if len(q) < 3:
        raise ApiError("query must be at least 3 characters")
    terms = set(re.findall(r"[a-z0-9_-]{3,}", q))
    ranked = []
    for item in _items(_int("days", 0, 0, 3650)):
        text = f"{item.get('title', '')} {item.get('text', '')} {item.get('summary', '')}".lower()
        hits = sum(1 for t in terms if t in text)
        if hits:
            ranked.append((hits, int((item.get("intelligence") or {}).get("risk_score", 0)), item))
    ranked.sort(key=lambda x: (x[0], x[1]), reverse=True)
    return jsonify({"query": q, "matches": [x[2] for x in ranked[:20]], "count": len(ranked)})


@app.route("/api/verified")
def verified():
    status = request.args.get("status", "")
    res = db.load_verifications(days=_int("days", 0, 0, 3650))
    if status:
        res = [r for r in res if r.get("verification_status") == status]
    return jsonify(_paginate(res, 50))


@app.route("/api/verified/<raw_id>")
def verified_detail(raw_id: str):
    for r in db.load_verifications(days=0):
        if r.get("raw_id") == raw_id:
            return jsonify(r)
    raise ApiError("not found", 404)


# ── dashboard (static) ────────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory(WEB_DIR, "index.html")


@app.route("/ui/<path:filename>")
def ui_assets(filename: str):
    return send_from_directory(WEB_DIR, filename)


def run(host: str = "127.0.0.1", port: int = 8000, debug: bool = False) -> None:
    logger.info("API + dashboard on http://%s:%d", host, port)
    app.run(host=host, port=port, debug=debug, threaded=True)
