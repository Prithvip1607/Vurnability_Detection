"""
NVD cross-reference — checks if a CVE ID found in an item already exists
in the NVD/NIST database and enriches the item with CVSS data if so.

Uses NVD REST API v2.0 (no key required, but key removes rate limits).
"""
from __future__ import annotations
import re
import time
from datetime import datetime, timedelta, timezone

import requests

from config.settings import NVD_API_KEY, NVD_BASE_URL
from utils.logger import get_logger
from utils.retry import retry

logger = get_logger("nvd_enricher")

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
_HEADERS = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
_CACHE: dict[str, dict] = {}   # simple in-process CVE cache


@retry(max_attempts=3, base_delay=10.0, exceptions=(requests.RequestException,))
def _fetch_cve(cve_id: str) -> dict | None:
    if cve_id in _CACHE:
        return _CACHE[cve_id]
    try:
        r = requests.get(
            NVD_BASE_URL,
            params={"cveId": cve_id},
            headers=_HEADERS,
            timeout=15,
        )
        if r.status_code == 404:
            return None
        r.raise_for_status()
        vulns = r.json().get("vulnerabilities", [])
        if not vulns:
            return None
        data = vulns[0].get("cve", {})
        result = {
            "cve_id":      cve_id,
            "description": _first_desc(data),
            "cvss_v3":     _cvss_v3(data),
            "cvss_v2":     _cvss_v2(data),
            "published":   data.get("published", ""),
            "modified":    data.get("lastModified", ""),
            "references":  [r["url"] for r in data.get("references", [])[:5]],
        }
        _CACHE[cve_id] = result
        return result
    except requests.RequestException as e:
        logger.warning("NVD fetch failed for %s: %s", cve_id, e)
        raise


def _first_desc(cve_data: dict) -> str:
    for d in cve_data.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def _cvss_v3(cve_data: dict) -> dict:
    metrics = cve_data.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            cvss = entries[0].get("cvssData", {})
            return {
                "score":    cvss.get("baseScore"),
                "severity": cvss.get("baseSeverity"),
                "vector":   cvss.get("vectorString"),
            }
    return {}


def _cvss_v2(cve_data: dict) -> dict:
    entries = cve_data.get("metrics", {}).get("cvssMetricV2", [])
    if entries:
        cvss = entries[0].get("cvssData", {})
        return {"score": cvss.get("baseScore"), "severity": entries[0].get("baseSeverity")}
    return {}


def enrich(item: dict) -> dict:
    """
    Extract CVE IDs from item, look each up in NVD, attach enrichment data.
    Returns the item with an added 'nvd_data' key (list of CVE records).
    """
    text = f"{item.get('title', '')} {item.get('text', '')[:2000]}"
    cve_ids = list({c.upper() for c in _CVE_RE.findall(text)})
    if not cve_ids:
        item["nvd_data"] = []
        return item

    nvd_records = []
    for cve_id in cve_ids[:5]:   # cap at 5 CVEs per item
        try:
            record = _fetch_cve(cve_id)
            if record:
                nvd_records.append(record)
            time.sleep(0.6)   # NVD polite rate: ~100 req/min without key
        except Exception as e:
            logger.error("NVD enrich failed for %s: %s", cve_id, e)

    item["nvd_data"] = nvd_records
    item["cve_ids"]  = [r["cve_id"] for r in nvd_records]
    return item
