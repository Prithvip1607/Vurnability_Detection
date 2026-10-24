"""Analyst verification store (append-only JSONL event log).

Each event records who decided what and when. The latest event for a finding
determines its current status; the full history is kept for audit.
"""
from __future__ import annotations

import json
import os
import threading
import uuid
from pathlib import Path

from utils.audit import (
    audit, EV_FINDING_REVIEWED, EV_FINDING_CONFIRMED, EV_FINDING_FALSE_POS,
    EV_FINDING_RESOLVED, EV_ANALYST_NOTE,
)
from utils.timeutil import now_iso

STATUSES = ("potential", "under_investigation", "confirmed", "false_positive", "resolved")
from config.settings import DATA_DIR
_FILE = Path(os.getenv("EVVP_DECISIONS_FILE", str(Path(DATA_DIR) / "analyst_decisions.jsonl")))
_lock = threading.Lock()
_AUDIT_EVENT = {
    "confirmed": EV_FINDING_CONFIRMED, "false_positive": EV_FINDING_FALSE_POS,
    "resolved": EV_FINDING_RESOLVED, "under_investigation": EV_FINDING_REVIEWED, "potential": EV_FINDING_REVIEWED,
}


def _read() -> list[dict]:
    if not _FILE.exists():
        return []
    out = []
    with _lock:
        try:
            for line in _FILE.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except OSError:
            return []
    return out


def record(entity: dict, status: str | None, analyst: str, notes: str = "", kind: str = "decision") -> dict:
    """Append a decision (kind='decision') or note (kind='note') for a finding."""
    analyst = (analyst or "").strip()
    notes = (notes or "").strip()
    if not analyst:
        raise ValueError("analyst name is required")
    if len(analyst) > 80:
        raise ValueError("analyst name is too long (max 80)")
    if len(notes) > 4000:
        raise ValueError("notes are too long (max 4000 characters)")
    current = (entity.get("analyst") or {}).get("status", "potential")
    if kind == "note":
        if not notes:
            raise ValueError("note text is required")
        status = current
    else:
        if status not in STATUSES:
            raise ValueError(f"status must be one of: {', '.join(STATUSES)}")
    event = {
        "id": uuid.uuid4().hex[:12], "ts": now_iso(), "kind": kind, "entity_id": entity["id"],
        "item_ids": entity.get("item_ids", []), "cve_ids": entity.get("cve_ids", []),
        "title": entity.get("title", "")[:200], "status": status, "previous_status": current,
        "analyst": analyst, "notes": notes,
    }
    with _lock:
        _FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
    audit(EV_ANALYST_NOTE if kind == "note" else _AUDIT_EVENT[status], actor=analyst, entity_id=entity["id"],
          cve_id=(entity.get("cve_ids") or [None])[0], title=event["title"], status=status, previous=current)
    return event


def latest_by_entity() -> dict[str, dict]:
    latest: dict[str, dict] = {}
    for ev in _read():                                   # file order == chronological
        eid = ev["entity_id"]
        prev = latest.get(eid)
        if ev.get("kind") == "note" and prev is not None and prev.get("kind") != "note":
            latest[eid] = {**prev, "last_note": ev}      # keep who decided; remember the newest note beside it
        elif ev.get("kind") != "note":
            latest[eid] = {**ev, **({"last_note": prev["last_note"]} if prev and prev.get("last_note") else {})}
        else:
            latest[eid] = ev
    return latest


def history(entity: dict) -> list[dict]:
    ids = set(entity.get("item_ids", []))
    return [e for e in _read() if e.get("entity_id") == entity["id"] or set(e.get("item_ids") or []) & ids]
