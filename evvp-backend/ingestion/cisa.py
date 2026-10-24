"""CISA Known Exploited Vulnerabilities (KEV) as a *source* (authoritative exploitation intelligence).

Every KEV entry is, by definition, exploited in the wild. Recent additions become findings (or evidence on a finding that already
tracks the CVE), so an early signal that later lands in KEV is confirmed by an authoritative source.
The listing date is date-only, so it is kept as metadata and NOT used as an observation time (no invented precision).
"""
from __future__ import annotations

import time

import requests

from config.settings import KEV_LOOKBACK_DAYS, KEV_URL, TICK_SECONDS
from pipeline.processor import process
from source_manager import manager
from storage.db import StorageError
from utils.audit import audit, EV_SOURCE_COLLECTED, EV_SOURCE_FETCH_FAIL
from utils.logger import get_logger
from utils.timeutil import parse_ts
from datetime import datetime, timedelta, timezone

logger = get_logger("ingestion.cisa")


def _to_item(v: dict) -> dict:
    cve = v["cveID"].upper()
    text = " ".join(x for x in (v.get("shortDescription"), f"Required action: {v['requiredAction']}" if v.get("requiredAction") else "",
                                "Known to be used in ransomware campaigns." if str(v.get("knownRansomwareCampaignUse")).lower() == "known" else "") if x)
    return {
        "id": f"cisa_{cve}", "platform": "cisa", "source": "cisa_kev", "author": "CISA", "timestamp": "",
        "title": f"{cve}: {v.get('vulnerabilityName') or (v.get('vendorProject', '') + ' ' + v.get('product', '')).strip()}",
        "text": f"{text} Exploited in the wild (CISA KEV).", "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
        "cve_ids": [cve], "kev": [{"cve_id": cve, "added": v.get("dateAdded"), "due": v.get("dueDate"), "ransomware": v.get("knownRansomwareCampaignUse")}],
        "metadata": {"vendor": v.get("vendorProject"), "product": v.get("product"), "date_added": v.get("dateAdded"), "source_type": "cisa_kev"},
    }


def run_once(force: bool = False) -> None:
    src = manager.gate("builtin-cisa-kev", force)
    if not src:
        return
    try:
        r = requests.get(KEV_URL, timeout=30, headers={"User-Agent": manager.USER_AGENT})
        r.raise_for_status()
        vulns = r.json().get("vulnerabilities")
        if not isinstance(vulns, list):
            raise ValueError("unexpected KEV format (no 'vulnerabilities' list)")
    except Exception as exc:
        manager.mark_fetch("builtin-cisa-kev", success=False, error=str(exc) or exc.__class__.__name__)
        audit(EV_SOURCE_FETCH_FAIL, source="CISA KEV", source_id="builtin-cisa-kev", error=str(exc)[:300])
        logger.error("CISA KEV fetch failed: %s", exc)
        return
    cutoff = datetime.now(timezone.utc) - timedelta(days=KEV_LOOKBACK_DAYS)
    saved = recent = 0
    for v in vulns:
        try:
            added = parse_ts(v.get("dateAdded"))
            if not v.get("cveID") or not added or added < cutoff:
                continue
            recent += 1
            if process(_to_item(v), force=True):
                saved += 1
        except StorageError as exc:
            manager.mark_fetch("builtin-cisa-kev", success=False, error=f"storage error: {exc}")
            audit(EV_SOURCE_FETCH_FAIL, source="CISA KEV", source_id="builtin-cisa-kev", error=f"storage error: {exc}"[:300])
            logger.error("CISA KEV: storage error, collection aborted: %s", exc)
            return
        except Exception as exc:
            logger.error("KEV entry skipped: %s", exc)
    manager.mark_fetch("builtin-cisa-kev", success=True, item_count=recent, new_items=saved)
    audit(EV_SOURCE_COLLECTED, source="CISA KEV", source_id="builtin-cisa-kev", fetched=recent, saved=saved)
    logger.info("CISA KEV — %d catalog entries, %d added in the last %d days, %d saved", len(vulns), recent, KEV_LOOKBACK_DAYS, saved)


def run_continuous() -> None:
    logger.info("CISA KEV collector started (interval comes from the Source Manager)")
    while True:
        try:
            run_once()
        except Exception as exc:
            logger.error("CISA cycle error: %s", exc)
        time.sleep(TICK_SECONDS)
