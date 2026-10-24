"""
Continuous update: findings whose CVE was not yet in NVD (or NVD was down) are retried periodically, so an
early signal is enriched automatically the moment the authoritative record appears.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from pipeline.epss import enrich_epss
from pipeline.nvd_enricher import enrich
from storage.db import load_recent_raw, update_raw
from utils.audit import audit, EV_NVD_ENRICHED
from utils.logger import get_logger
from utils.timeutil import parse_ts

logger = get_logger("reenrich")
RETRY_STATUSES = {"unavailable", "not_found", "partial"}


def run(max_items: int = 25, max_age_days: int = 14) -> int:
    """Re-check up to ``max_items`` stale findings. Returns how many gained new NVD data."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
    candidates = [i for i in load_recent_raw(days=max_age_days)
                  if i.get("cve_ids") and i.get("nvd_status") in RETRY_STATUSES and i.get("platform") != "nvd"]
    candidates.sort(key=lambda i: str(i.get("collected_at") or ""))
    updated = 0
    for it in candidates[:max_items]:
        if (parse_ts(it.get("collected_at")) or cutoff) < cutoff:
            continue
        before = len(it.get("nvd_data") or [])

        def mutate(obj: dict, _before=before) -> bool:
            enrich(obj)
            enrich_epss(obj)
            return len(obj.get("nvd_data") or []) > _before or obj.get("nvd_status") == "ok"

        if update_raw(it["id"], mutate):
            updated += 1
            audit(EV_NVD_ENRICHED, platform=it.get("platform"), cve_id=it["cve_ids"][0], reason="re-enrichment")
    if updated:
        logger.info("Re-enrichment added NVD data to %d finding(s)", updated)
    return updated
