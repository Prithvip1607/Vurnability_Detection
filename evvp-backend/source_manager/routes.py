"""REST endpoints for the Source Manager (/api/sources). All writes are audited with the acting analyst."""
from __future__ import annotations

import threading

from flask import Blueprint, jsonify, request

from source_manager import manager as m
from utils.audit import (audit, EV_SOURCE_ADDED, EV_SOURCE_DELETED, EV_SOURCE_DISABLED, EV_SOURCE_EDITED,
                         EV_SOURCE_ENABLED, EV_SOURCE_TESTED, EV_SOURCE_COLLECT_TRIGGERED)

sources_bp = Blueprint("sources", __name__, url_prefix="/api/sources")


def _body() -> dict:
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _actor(data: dict) -> str:
    return str(data.get("actor") or "analyst")[:80]


def _err(msg: str, code: int):
    return jsonify({"error": msg}), code


@sources_bp.get("")
def list_all():
    return jsonify({"sources": m.list_sources(), "options": m.options()})


@sources_bp.post("")
def create():
    data = _body()
    try:
        item = m.add_source(data)
    except m.SourceError as exc:
        return _err(str(exc), 400)
    audit(EV_SOURCE_ADDED, actor=_actor(data), source=item["name"], source_id=item["id"], url=item["url"], mapping=item.get("mapping"),
          type=item["type"], trust=item["trust"], category=item["category"], interval_minutes=item["interval_minutes"])
    return jsonify(item), 201


@sources_bp.post("/test")
def test_url():
    """Dry-run a URL before it is added; nothing is stored."""
    data = _body()
    try:
        result = m.test_source(data.get("url", ""), data.get("type", "rss"), mapping=data.get("mapping"))
        audit(EV_SOURCE_TESTED, actor=_actor(data), url=str(data.get("url"))[:300], valid=True)
        return jsonify(result)
    except m.SourceError as exc:
        audit(EV_SOURCE_TESTED, actor=_actor(data), url=str(data.get("url"))[:300], valid=False, error=str(exc))
        return jsonify({"valid": False, "error": str(exc)}), 422


@sources_bp.post("/<source_id>/test")
def test_saved(source_id: str):
    data = _body()
    src = m.get_source(source_id)
    if not src:
        return _err("Source not found", 404)
    try:
        result = m.test_source(src["url"], src["type"], mapping=src.get("mapping"))
        m.record_test(source_id, True)
        audit(EV_SOURCE_TESTED, actor=_actor(data), source=src["name"], source_id=source_id, valid=True)
        return jsonify(result)
    except m.SourceError as exc:
        m.record_test(source_id, False, str(exc))
        audit(EV_SOURCE_TESTED, actor=_actor(data), source=src["name"], source_id=source_id, valid=False, error=str(exc))
        return jsonify({"valid": False, "error": str(exc)}), 422


@sources_bp.post("/<source_id>/collect")
def collect_now(source_id: str):
    """Run one collection for this RSS/Atom source in the background."""
    src = m.get_source(source_id)
    if not src:
        return _err("Source not found", 404)
    if not m.generic(src):
        return _err("Built-in sources run on their own schedule; API/custom sources need a field mapping to be collected", 400)
    if not src["enabled"]:
        return _err("Source is disabled; enable it first", 400)
    from ingestion import blog
    audit(EV_SOURCE_COLLECT_TRIGGERED, actor=_actor(_body()), source=src["name"], source_id=source_id)
    threading.Thread(target=blog.collect_source, args=(src,), daemon=True, name=f"collect-{source_id}").start()
    return jsonify({"started": True, "source_id": source_id}), 202


@sources_bp.patch("/<source_id>")
def patch(source_id: str):
    data = _body()
    before = m.get_source(source_id)
    if not before:
        return _err("Source not found", 404)
    changes = {k: v for k, v in data.items() if k != "actor"}
    try:
        after = m.update_source(source_id, changes)
    except m.SourceError as exc:
        return _err(str(exc), 400)
    except KeyError:
        return _err("Source not found", 404)
    actor = _actor(data)
    diff = {k: [before.get(k), after.get(k)] for k in ("name", "url", "type", "category", "trust", "interval_minutes", "mapping")
            if k in changes and before.get(k) != after.get(k)}
    if diff:
        audit(EV_SOURCE_EDITED, actor=actor, source=after["name"], source_id=source_id, changes=diff)
    if "enabled" in changes and before["enabled"] != after["enabled"]:
        audit(EV_SOURCE_ENABLED if after["enabled"] else EV_SOURCE_DISABLED, actor=actor, source=after["name"], source_id=source_id)
    return jsonify(after)


@sources_bp.delete("/<source_id>")
def remove(source_id: str):
    data = _body()
    src = m.get_source(source_id)
    if not src:
        return _err("Source not found", 404)
    try:
        m.delete_source(source_id)
    except m.SourceError as exc:
        return _err(str(exc), 400)
    except KeyError:
        return _err("Source not found", 404)
    audit(EV_SOURCE_DELETED, actor=_actor(data), source=src["name"], source_id=source_id, url=src["url"])
    return jsonify({"success": True})
