"""NVD cross-reference: attach CVSS / description / references to CVEs named in an item.

Failure model (never raises, never loses the CVE id):
  nvd_status = "ok"           every CVE found in NVD
               "partial"      some found, some unavailable/missing
               "not_found"    NVD answered but has no record yet (CVE very new / reserved)
               "unavailable"  NVD could not be reached (timeout, 429, 5xx, bad JSON)
Findings with status not_found/unavailable/partial are re-checked later by pipeline.reenrich.
"""
from __future__ import annotations

import re
import threading
import time

import requests

from config.settings import NVD_API_KEY, NVD_BASE_URL, NVD_MIN_INTERVAL, USER_AGENT
from utils.logger import get_logger

logger = get_logger("nvd_enricher")

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_CACHE: dict[str, dict] = {}            # successful lookups only
_CACHE_LOCK = threading.Lock()


def _headers() -> dict:
    h = {"User-Agent": USER_AGENT}
    if NVD_API_KEY:
        h["apiKey"] = NVD_API_KEY
    return h


_throttle_lock = threading.Lock()
_last_request = 0.0


def throttle() -> None:
    """Block until NVD's rate limit allows another request (shared by every NVD caller in this process)."""
    global _last_request
    if NVD_MIN_INTERVAL <= 0:
        return
    with _throttle_lock:
        wait = _last_request + NVD_MIN_INTERVAL - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        _last_request = time.monotonic()


def parse_nvd_cve(data: dict) -> dict:
    """Convert an NVD API 2.0 ``cve`` object into EVVP's compact record."""
    return {
        "cve_id": data.get("id", ""),
        "description": _first_desc(data),
        "cvss_v3": _cvss_v3(data),
        "cvss_v2": _cvss_v2(data),
        "published": data.get("published", ""),
        "modified": data.get("lastModified", ""),
        "references": [r["url"] for r in data.get("references", []) if r.get("url")][:10],
        "affected_products": _products(data),
    }


def _fetch_cve(cve_id: str) -> dict | None:
    """Return the NVD record, or None if NVD has no such CVE. Raises requests.RequestException on outage."""
    with _CACHE_LOCK:
        if cve_id in _CACHE:
            return _CACHE[cve_id]
    last_exc: Exception | None = None
    for attempt in range(2):
        try:
            throttle()
            r = requests.get(NVD_BASE_URL, params={"cveId": cve_id}, headers=_headers(), timeout=15)
            if r.status_code == 404:
                return None
            if r.status_code in (403, 429) or r.status_code >= 500:     # rate limited / NVD outage
                raise requests.HTTPError(f"NVD HTTP {r.status_code}")
            r.raise_for_status()
            vulns = r.json().get("vulnerabilities", [])
            if not vulns:
                return None
            record = parse_nvd_cve(vulns[0].get("cve", {}))
            record["cve_id"] = record["cve_id"] or cve_id
            with _CACHE_LOCK:
                _CACHE[cve_id] = record
            return record
        except (requests.RequestException, ValueError) as exc:
            last_exc = exc
            if attempt == 0:
                time.sleep(2.0)
    logger.warning("NVD lookup failed for %s: %s", cve_id, last_exc)
    raise requests.RequestException(str(last_exc))


def _first_desc(cve_data: dict) -> str:
    for d in cve_data.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def _cvss_v3(cve_data: dict) -> dict:
    """Best CVSS base score: v3.1, then v3.0, then v4.0 (newer CVEs may only have v4). NVD's own ("Primary") assessment wins over a CNA's."""
    metrics = cve_data.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
        entries = metrics.get(key, [])
        if entries:
            entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
            cvss = entry.get("cvssData", {})
            if cvss.get("baseScore") is None:
                continue
            return {"score": cvss.get("baseScore"), "severity": cvss.get("baseSeverity"), "vector": cvss.get("vectorString"), "version": cvss.get("version")}
    return {}


def _cvss_v2(cve_data: dict) -> dict:
    entries = cve_data.get("metrics", {}).get("cvssMetricV2", [])
    if entries:
        cvss = entries[0].get("cvssData", {})
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        return {"score": entry.get("cvssData", {}).get("baseScore"), "severity": entry.get("baseSeverity")}
    return {}


def _products(cve_data: dict) -> list[str]:
    """Affected vendor:product pairs from CPE match criteria (best effort)."""
    out: list[str] = []
    for conf in cve_data.get("configurations", []) or []:
        for node in conf.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                parts = (m.get("criteria") or "").split(":")
                if len(parts) > 5 and m.get("vulnerable", True):
                    name = f"{parts[3]} {parts[4]}".replace("_", " ")
                    if name not in out:
                        out.append(name)
    return out[:10]


def item_cve_ids(item: dict) -> list[str]:
    text = f"{item.get('title', '')} {(item.get('text') or '')[:2000]}"
    found = {c.upper() for c in _CVE_RE.findall(text)} | {c.upper() for c in (item.get("cve_ids") or [])}
    return sorted(found)


def enrich(item: dict) -> dict:
    """Extract CVE ids from the item and look each up in NVD. Never raises."""
    cve_ids = item_cve_ids(item)
    have = {(r.get("cve_id") or "").upper(): r for r in (item.get("nvd_data") or [])}
    if not cve_ids:
        item["nvd_data"] = []
        item.pop("nvd_status", None)
        return item

    records, failed, missing = [], 0, 0
    for cve_id in cve_ids[:5]:
        if cve_id in have:                          # already enriched (e.g. NVD-sourced item)
            records.append(have[cve_id])
            continue
        try:
            rec = _fetch_cve(cve_id)
            if rec:
                records.append(rec)
            else:
                missing += 1
        except requests.RequestException:
            failed += 1

    item["cve_ids"] = cve_ids                       # the CVE id is evidence even if NVD can't confirm it
    item["nvd_data"] = records
    n = len(cve_ids[:5])
    if len(records) == n:
        item["nvd_status"] = "ok"
    elif records:
        item["nvd_status"] = "partial"
    elif failed:
        item["nvd_status"] = "unavailable"
    else:
        item["nvd_status"] = "not_found"
    return item
