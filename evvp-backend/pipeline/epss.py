"""FIRST EPSS enrichment. Fail-open: EVVP keeps working when the API is unreachable."""
from __future__ import annotations

import requests

from datetime import datetime, timezone

from config.settings import EPSS_URL, USER_AGENT
from utils.logger import get_logger

logger = get_logger("epss")
BASE = EPSS_URL


def enrich_epss(item: dict) -> dict:
    cves = item.get("cve_ids") or []
    if not cves:
        return item
    uniq = list(dict.fromkeys(c.upper() for c in cves))[:5]
    values = []
    try:
        r = requests.get(BASE, params={"cve": ",".join(uniq)}, timeout=15, headers={"User-Agent": USER_AGENT})    # one batched request
        r.raise_for_status()
        for d in r.json().get("data", []):
            values.append({"cve_id": d["cve"].upper(), "epss": float(d.get("epss", 0)),
                           "percentile": float(d.get("percentile", 0)), "date": d.get("date")})
    except Exception as exc:                          # network, HTTP, JSON, schema
        logger.debug("EPSS lookup failed for %s: %s", uniq, exc)
        return item
    if values:
        item["epss_data"] = values
        item["epss"] = max(v["epss"] for v in values)
        item["epss_percentile"] = max(v["percentile"] for v in values)
        item["epss_checked_at"] = datetime.now(timezone.utc).isoformat()
    return item
