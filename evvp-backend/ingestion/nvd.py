"""
NVD ingestion — polls the NVD REST API v2.0 for recently published CVEs.
Stores them as raw intel items so the dashboard can show newly disclosed CVEs
even before they appear in Reddit/GitHub/blog discussions.
"""
import time
from datetime import datetime, timedelta, timezone

import requests

from config.settings import NVD_API_KEY, NVD_BASE_URL, NVD_POLL_INTERVAL, NVD_LOOKBACK_DAYS
from pipeline.processor import process
from utils.logger import get_logger
from utils.retry import retry

logger  = get_logger("ingestion.nvd")
_HDRS   = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}


@retry(max_attempts=3, base_delay=15.0, exceptions=(requests.RequestException,))
def _fetch_recent_cves(start_dt: datetime, end_dt: datetime) -> list[dict]:
    params = {
        "pubStartDate": start_dt.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate":   end_dt.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 100,
    }
    r = requests.get(NVD_BASE_URL, headers=_HDRS, params=params, timeout=30)
    r.raise_for_status()
    return r.json().get("vulnerabilities", [])


def _vuln_to_item(vuln: dict) -> dict:
    cve = vuln.get("cve", {})
    cve_id = cve.get("id", "")

    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break

    cvss_score = None
    severity   = ""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = cve.get("metrics", {}).get(key, [])
        if entries:
            cvss_score = entries[0].get("cvssData", {}).get("baseScore")
            severity   = entries[0].get("cvssData", {}).get("baseSeverity", "")
            break

    refs = [r["url"] for r in cve.get("references", [])[:5]]

    return {
        "id":       f"nvd_{cve_id}",
        "platform": "nvd",
        "source":   "nvd_api",
        "title":    cve_id,
        "text":     desc,
        "author":   "NVD/NIST",
        "timestamp": cve.get("published", ""),
        "url":      f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "metadata": {
            "cve_id":     cve_id,
            "cvss_score": cvss_score,
            "severity":   severity,
            "references": refs,
            "source_type": "nvd",
        },
    }


def run_once() -> None:
    end   = datetime.now(timezone.utc)
    start = end - timedelta(days=NVD_LOOKBACK_DAYS)
    try:
        vulns = _fetch_recent_cves(start, end)
        saved = 0
        for vuln in vulns:
            item = _vuln_to_item(vuln)
            # Force NVD items through pipeline — they always have CVE IDs
            # so signal filter will give them a CVE bonus
            if process(item):
                saved += 1
        logger.info("NVD — %d CVEs fetched, %d saved", len(vulns), saved)
    except Exception as e:
        logger.error("NVD fetch failed: %s", e)


def run_continuous() -> None:
    logger.info("NVD ingestion started (interval=%ds)", NVD_POLL_INTERVAL)
    while True:
        try:
            run_once()
        except Exception as e:
            logger.error("NVD cycle error: %s", e)
        time.sleep(NVD_POLL_INTERVAL)
