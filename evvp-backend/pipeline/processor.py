"""
Pipeline orchestrator — every collected item passes through:
  1. Signal scoring   (signal_filter)
  2. NVD enrichment   (nvd_enricher)
  3. Novelty check    (novelty)
  4. Storage          (storage.db)
  5. CVE trend track  (tracker)
  6. Notification     (notifier)
  7. Audit log        (utils.audit)
"""
from __future__ import annotations
import re
import uuid
from datetime import datetime, timezone

from pipeline.signal_filter import analyze
from pipeline.nvd_enricher  import enrich
from pipeline.novelty        import check as novelty_check
from pipeline.tracker        import record as track_cves
from pipeline.notifier       import dispatch
from pipeline.verifier       import verify
from storage.db              import save_raw, save_verified, save_verification, load_recent_raw
from utils.audit             import audit, EV_ITEM_COLLECTED, EV_ITEM_PASSED, EV_ITEM_DROPPED, \
                                     EV_ITEM_DUPLICATE, EV_ITEM_NOVEL, EV_NVD_ENRICHED, \
                                     EV_STORAGE_SAVED, EV_NOTIFICATION_SENT
from utils.logger            import get_logger

logger  = get_logger("pipeline")
_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

_recent_cache: list[dict] = []
_cache_counter = 0
_CACHE_REFRESH  = 50


def _refresh_cache() -> None:
    global _recent_cache
    _recent_cache = load_recent_raw(days=30)


def process(item: dict) -> bool:
    global _cache_counter

    platform = item.get("platform", "?")
    title    = item.get("title", "")[:120]

    # Audit: raw item received
    audit(EV_ITEM_COLLECTED, platform=platform, title=title, url=item.get("url", ""))

    # 1. Signal scoring
    result = analyze(item)
    if not result.passes:
        audit(EV_ITEM_DROPPED,
              platform=platform, title=title,
              reason="low_signal", score=result.signal_score, category=result.category)
        return False

    item["signal_score"]     = result.signal_score
    item["category"]         = result.category
    item["matched_signals"]  = result.matched_signals
    item["negative_signals"] = result.negative_signals

    audit(EV_ITEM_PASSED,
          platform=platform, title=title,
          score=result.signal_score, category=result.category,
          matched=result.matched_signals[:5])

    # 2. NVD enrichment
    item = enrich(item)
    if item.get("nvd_data"):
        audit(EV_NVD_ENRICHED,
              platform=platform,
              cve_ids=item.get("cve_ids", []),
              nvd_count=len(item["nvd_data"]))

    # 3. Novelty check
    if _cache_counter % _CACHE_REFRESH == 0:
        _refresh_cache()
    _cache_counter += 1
    novelty = novelty_check(item, existing=_recent_cache)

    if not novelty.is_novel:
        audit(EV_ITEM_DUPLICATE,
              platform=platform, title=title,
              reason=novelty.reason, duplicate_of=novelty.duplicate_id)

    # 4. Persist raw item
    if not item.get("id"):
        item["id"] = str(uuid.uuid4())
    item["collected_at"] = datetime.now(timezone.utc).isoformat()
    save_raw(item)
    audit(EV_STORAGE_SAVED, platform=platform, item_id=item["id"])

    # 5. Persist verified record
    severity = _estimate_severity(item)
    save_verified({
        "id":                str(uuid.uuid4()),
        "raw_id":            item["id"],
        "cve_ids":           item.get("cve_ids", []),
        "is_novel":          novelty.is_novel,
        "novelty_reason":    novelty.reason,
        "severity_estimate": severity,
        "metadata": {
            "nvd_data":        item.get("nvd_data", []),
            "duplicate_of":    novelty.duplicate_id,
            "signal_score":    item["signal_score"],
            "category":        item["category"],
            "matched_signals": item["matched_signals"],
        },
    })

    # 5b. Phase 3 — Verification Engine (runs on novel items only)
    if novelty.is_novel:
        try:
            vr = verify(item, cross_source_count=1)
            vr["id"] = str(uuid.uuid4())
            save_verification(vr)
            item["verification"] = vr
            logger.info("[VERIFY] status=%s cred=%d poc=%s | %.60s",
                        vr["verification_status"], vr["credibility_score"],
                        vr["poc_found"], title)
        except Exception as e:
            logger.error("Verifier failed for %s: %s", item.get("id"), e)

    # 6. CVE trend tracking
    cve_ids = item.get("cve_ids") or list(set(_CVE_RE.findall(
        f"{item.get('title', '')} {item.get('text', '')[:500]}"
    )))
    if cve_ids:
        track_cves([c.upper() for c in cve_ids], item)

    # 7. Notify on novel items
    if novelty.is_novel:
        audit(EV_ITEM_NOVEL,
              platform=platform, title=title,
              cve_id=cve_ids[0] if cve_ids else None,
              score=item["signal_score"], severity=severity)
        dispatch({
            "type":         "new_vulnerability" if cve_ids else "zero_day_detected",
            "cve_id":       cve_ids[0] if cve_ids else None,
            "title":        item.get("title", ""),
            "platform":     platform,
            "url":          item.get("url", ""),
            "signal_score": item["signal_score"],
            "severity":     severity,
            "sources":      [platform],
            "mention_count": 1,
            "detected_at":  item["collected_at"],
        })
        audit(EV_NOTIFICATION_SENT,
              platform=platform,
              cve_id=cve_ids[0] if cve_ids else None,
              severity=severity)

    logger.info("[%s] score=%d novel=%s severity=%s | %.80s",
                platform.upper(), item["signal_score"], novelty.is_novel, severity, title)
    return True


def _estimate_severity(item: dict) -> str:
    nvd = item.get("nvd_data", [])
    if nvd:
        scores = [n.get("cvss_v3", {}).get("score") for n in nvd if n.get("cvss_v3", {}).get("score")]
        if scores:
            top = max(scores)
            if top >= 9.0: return "CRITICAL"
            if top >= 7.0: return "HIGH"
            if top >= 4.0: return "MEDIUM"
            return "LOW"
    score   = item.get("signal_score", 0)
    matched = set(s.lower() for s in item.get("matched_signals", []))
    critical_terms = {
        "actively exploited", "exploited in the wild", "0day", "zero-day",
        "unauthenticated rce", "sandbox escape", "kernel exploit", "working exploit",
    }
    if score >= 20 or matched & critical_terms: return "CRITICAL"
    if score >= 14:                              return "HIGH"
    if score >= 8:                               return "MEDIUM"
    return "LOW"
