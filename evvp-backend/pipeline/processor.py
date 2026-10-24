"""Pipeline orchestrator — every collected item passes through:

  1. Signal scoring      (signal_filter)        drop noise
  2. Source trust        (source manager)       how credible is the publisher?
  3. CVE enrichment      (NVD, EPSS, CISA KEV)  authoritative data; failures never lose the CVE id
  4. Summary             (summarizer)
  5. Novelty / dedupe    (novelty)              duplicates become *evidence* on the existing finding
  6. Intelligence        (risk)                 risk breakdown, zero-day candidate, ATT&CK
  7. Storage, verification, CVE trend tracking, notification, audit
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone

from config.settings import TRUST_WEIGHT
from pipeline.entities import _evidence_type, source_key, source_label
from pipeline.epss import enrich_epss
from pipeline.kev import enrich_kev
from pipeline.notifier import dispatch
from pipeline.novelty import check as novelty_check
from pipeline.nvd_enricher import enrich
from pipeline.risk import build_intelligence
from pipeline.signal_filter import analyze
from pipeline.summarizer import generate_summary
from pipeline.tracker import record as track_cves
from pipeline.verifier import verify
from storage.db import append_source, load_recent_raw, save_raw, save_verification, save_verified, update_raw
from utils.audit import (audit, EV_ITEM_COLLECTED, EV_ITEM_DROPPED, EV_ITEM_DUPLICATE, EV_ITEM_NOVEL,
                         EV_ITEM_PASSED, EV_NVD_ENRICHED, EV_STORAGE_SAVED)
from utils.logger import get_logger
from utils.timeutil import iso, parse_ts

logger = get_logger("pipeline")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

_recent_cache: list[dict] = []
_cache_counter = 0
_CACHE_REFRESH = 50
_BUILTIN_FOR_PLATFORM = {"nvd": "builtin-nvd", "github": "builtin-github", "reddit": "builtin-reddit", "cisa": "builtin-cisa-kev"}


def _refresh_cache() -> None:
    global _recent_cache
    _recent_cache = load_recent_raw(days=30)


def _apply_trust(item: dict) -> None:
    """Make sure every item carries its source's trust level (analyst-configurable, never assumed)."""
    md = item.setdefault("metadata", {})
    if not item.get("source_trust"):
        trust, category, name = "medium", None, None
        try:
            from source_manager import manager
            sid = _BUILTIN_FOR_PLATFORM.get(item.get("platform", ""))
            src = manager.get_source(sid) if sid else None
            if src:
                trust, category, name = src["trust"], src["category"], src["name"]
        except Exception as exc:                       # trust lookup must never block collection
            logger.debug("trust lookup failed: %s", exc)
        item["source_trust"] = trust
        md.setdefault("source_category", category)
        md.setdefault("source_name", name)
    item.setdefault("source_trust_weight", TRUST_WEIGHT.get(item["source_trust"], 55))
    md["source_trust"] = item["source_trust"]


def _enrich(item: dict, platform: str) -> dict:
    """NVD → EPSS → KEV. Each stage is isolated: an outage degrades the finding, never drops it."""
    try:
        item = enrich(item)
    except Exception as exc:
        logger.error("NVD enrichment error: %s", exc)
        item.setdefault("nvd_data", [])
        item["nvd_status"] = "unavailable"
    if not item.get("cve_ids"):
        item["cve_ids"] = sorted({c.upper() for c in _CVE_RE.findall(f"{item.get('title', '')} {(item.get('text') or '')[:2000]}")})
    if item.get("nvd_data"):
        audit(EV_NVD_ENRICHED, platform=platform, cve_ids=item.get("cve_ids", []), nvd_count=len(item["nvd_data"]))
    for fn in (enrich_epss, enrich_kev):
        try:
            item = fn(item)
        except Exception as exc:
            logger.warning("%s failed: %s", fn.__name__, exc)
    return item


def _publisher_count(item: dict, existing: list[dict]) -> int:
    """Independent publishers already covering the same CVE or a very similar story."""
    keys = {source_key(source_label(item))}
    cves = {c.upper() for c in (item.get("cve_ids") or [])}
    from pipeline.novelty import _same_story
    for old in existing:
        old_cves = {c.upper() for c in (old.get("cve_ids") or [])}
        if (cves and old_cves & cves) or (item.get("title") and _same_story(item["title"], old.get("title", ""))):
            keys.add(source_key(source_label(old)))
            for extra in old.get("sources") or []:
                if extra.get("source"):
                    keys.add(source_key(extra["source"]))
    keys.discard("")
    return max(1, len(keys))


def _estimate_severity(item: dict) -> str:
    nvd = item.get("nvd_data", [])
    scores = [n.get("cvss_v3", {}).get("score") for n in nvd if (n.get("cvss_v3") or {}).get("score")]
    if scores:
        top = max(scores)
        return "CRITICAL" if top >= 9.0 else "HIGH" if top >= 7.0 else "MEDIUM" if top >= 4.0 else "LOW"
    score = item.get("signal_score", 0)
    matched = {s.lower() for s in item.get("matched_signals", [])}
    critical = {"actively exploited", "exploited in the wild", "0day", "zero-day", "unauthenticated rce",
                "sandbox escape", "kernel exploit", "working exploit"}
    if score >= 20 or matched & critical:
        return "CRITICAL"
    return "HIGH" if score >= 14 else "MEDIUM" if score >= 8 else "LOW"


def _absorb_duplicate(item: dict, dup_id: str, reason: str, platform: str) -> None:
    """A duplicate is *evidence* for the existing finding: keep who said it, when, and how credible."""
    if reason in ("exact_id_match", "url_match"):
        return                                                  # same record re-collected: nothing new
    entry = {
        "source": source_label(item), "observed_at": iso(parse_ts(item.get("timestamp"))),
        "collected_at": datetime.now(timezone.utc).isoformat(), "trust": item.get("source_trust"),
        "evidence_type": _evidence_type(item), "title": item.get("title", "")[:200],
    }
    if item.get("url"):
        append_source(dup_id, item["url"], item.get("platform", platform), extra={k: v for k, v in entry.items() if v})

    def merge(obj: dict) -> bool:                               # new authoritative data upgrades the finding
        changed = False
        for key in ("nvd_data", "epss_data", "kev"):
            if item.get(key) and not obj.get(key):
                obj[key] = item[key]; changed = True
        for key in ("epss", "epss_percentile", "nvd_status"):
            if item.get(key) is not None and obj.get(key) is None:
                obj[key] = item[key]; changed = True
        new_cves = sorted(set(obj.get("cve_ids") or []) | set(item.get("cve_ids") or []))
        if new_cves != sorted(obj.get("cve_ids") or []):
            obj["cve_ids"] = new_cves; changed = True
        return changed
    if item.get("nvd_data") or item.get("kev") or item.get("cve_ids"):
        update_raw(dup_id, merge)


def process(item: dict, force: bool = False) -> bool:
    """Run one collected item through the pipeline. ``force`` skips only the noise filter
    (used for authoritative records such as an NVD entry for a CVE we already track)."""
    global _cache_counter
    platform = item.get("platform", "?")
    title = (item.get("title") or "")[:120]
    audit(EV_ITEM_COLLECTED, platform=platform, title=title, url=item.get("url", ""))

    result = analyze(item)
    if not result.passes and not force:
        audit(EV_ITEM_DROPPED, platform=platform, title=title, reason="low_signal",
              score=result.signal_score, category=result.category)
        return False
    item.update(signal_score=result.signal_score, category=result.category,
                matched_signals=result.matched_signals, negative_signals=result.negative_signals)
    audit(EV_ITEM_PASSED, platform=platform, title=title, score=result.signal_score,
          category=result.category, matched=result.matched_signals[:5])

    _apply_trust(item)
    item = _enrich(item, platform)

    try:
        item["summary"] = generate_summary(item)
    except Exception as exc:
        logger.warning("Summary generation failed: %s", exc)
        item["summary"] = ""

    if _cache_counter % _CACHE_REFRESH == 0:
        _refresh_cache()
    _cache_counter += 1
    novelty = novelty_check(item, existing=_recent_cache)

    csc = _publisher_count(item, _recent_cache)
    item["cross_source_count"] = csc
    item["intelligence"] = build_intelligence(item, csc)

    if not novelty.is_novel:
        audit(EV_ITEM_DUPLICATE, platform=platform, title=title, reason=novelty.reason, duplicate_of=novelty.duplicate_id)
        if novelty.duplicate_id:
            _absorb_duplicate(item, novelty.duplicate_id, novelty.reason, platform)
        return False

    if not item.get("id"):
        item["id"] = str(uuid.uuid4())
    item["collected_at"] = datetime.now(timezone.utc).isoformat()
    item.setdefault("sources", [{"url": item.get("url", ""), "platform": platform}])
    save_raw(item)
    _recent_cache.append(item)
    audit(EV_STORAGE_SAVED, platform=platform, item_id=item["id"])

    severity = _estimate_severity(item)
    save_verified({
        "id": str(uuid.uuid4()), "raw_id": item["id"], "cve_ids": item.get("cve_ids", []),
        "is_novel": True, "novelty_reason": novelty.reason, "severity_estimate": severity,
        "metadata": {"nvd_data": item.get("nvd_data", []), "signal_score": item["signal_score"],
                     "category": item["category"], "matched_signals": item["matched_signals"]},
    })

    try:
        vr = verify(item, cross_source_count=csc)
        vr["id"] = str(uuid.uuid4())
        save_verification(vr)
        item["verification"] = vr
    except Exception as exc:
        logger.error("Verifier failed for %s: %s", item.get("id"), exc)

    cve_ids = item.get("cve_ids") or []
    if cve_ids:
        try:
            track_cves([c.upper() for c in cve_ids], item)
        except Exception as exc:
            logger.warning("CVE tracking failed: %s", exc)

    audit(EV_ITEM_NOVEL, platform=platform, title=title, cve_id=cve_ids[0] if cve_ids else None,
          score=item["signal_score"], severity=severity)
    try:
        dispatch({
            "type": "new_vulnerability" if cve_ids else "zero_day_detected",
            "cve_id": cve_ids[0] if cve_ids else None, "title": item.get("title", ""), "platform": platform,
            "url": item.get("url", ""), "signal_score": item["signal_score"], "severity": severity,
            "sources": [platform], "mention_count": 1, "detected_at": item["collected_at"],
        })
    except Exception as exc:
        logger.warning("Notification failed: %s", exc)
    logger.info("[%s] score=%d severity=%s | %.80s", platform.upper(), item["signal_score"], severity, title)
    return True
