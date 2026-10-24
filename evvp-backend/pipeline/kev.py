"""CISA Known Exploited Vulnerabilities (KEV) enrichment.

A CVE in KEV has *confirmed* in-the-wild exploitation by an authoritative source,
which is stronger evidence than a blog saying "exploited". Fail-open and cached.
"""
from __future__ import annotations

import threading
import time

import requests

from config.settings import KEV_TTL_HOURS, KEV_URL, USER_AGENT
from utils.logger import get_logger

logger = get_logger("kev")
_lock = threading.Lock()
_cache: dict = {"ts": 0.0, "ids": {}}


def _load() -> dict:
    with _lock:
        if time.time() - _cache["ts"] < KEV_TTL_HOURS * 3600 and _cache["ids"]:
            return _cache["ids"]
    try:
        r = requests.get(KEV_URL, timeout=30, headers={"User-Agent": USER_AGENT})
        r.raise_for_status()
        ids = {v["cveID"].upper(): {"due": v.get("dueDate"), "added": v.get("dateAdded"),
                                    "ransomware": v.get("knownRansomwareCampaignUse")}
               for v in r.json().get("vulnerabilities", []) if v.get("cveID")}
        with _lock:
            _cache.update(ts=time.time(), ids=ids)
        return ids
    except Exception as exc:
        logger.warning("CISA KEV unavailable: %s", exc)
        with _lock:
            _cache["ts"] = time.time() - KEV_TTL_HOURS * 3600 + 600   # retry in ~10 minutes
            return _cache["ids"]


def enrich_kev(item: dict) -> dict:
    cves = item.get("cve_ids") or []
    if not cves:
        return item
    kev = _load()
    hits = [{"cve_id": c.upper(), **kev[c.upper()]} for c in cves if c.upper() in kev]
    if hits:
        item["kev"] = hits
    return item
