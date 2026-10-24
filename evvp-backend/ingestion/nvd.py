"""NVD ingestion — polls the NVD REST API v2.0 for recently published CVEs.

NVD is the *authoritative confirmation* layer, not the discovery layer. A CVE is stored when
  • it is one EVVP already tracks (so the early signal is linked to its official record and the
    early-detection lead time can be measured), or
  • it is critical (CVSS >= 9.0), or
  • it passes the normal security-signal filter.
Everything else is skipped to keep the dashboard free of thousands of unrelated CVEs.
"""
from __future__ import annotations

import re
import time
from datetime import datetime, timedelta, timezone

import requests

from config.settings import TICK_SECONDS
from config.settings import NVD_API_KEY, NVD_BASE_URL, NVD_LOOKBACK_DAYS
from pipeline.nvd_enricher import _headers, parse_nvd_cve, throttle
from pipeline.processor import process
from source_manager import manager
from storage.db import StorageError, load_recent_raw
from utils.audit import audit, EV_NVD_FETCH_FAIL
from utils.logger import get_logger

logger = get_logger("ingestion.nvd")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
PAGE_SIZE = 500
MAX_PAGES = 6
CRITICAL_CVSS = 9.0


def _fetch_page(start: datetime, end: datetime, index: int) -> dict:
    params = {"pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"), "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
              "resultsPerPage": PAGE_SIZE, "startIndex": index}
    headers = _headers()
    last: Exception | None = None
    for attempt in range(3):
        try:
            throttle()
            r = requests.get(NVD_BASE_URL, headers=headers, params=params, timeout=30)
            if r.status_code in (403, 429) or r.status_code >= 500:
                raise requests.HTTPError(f"NVD HTTP {r.status_code}")
            r.raise_for_status()
            return r.json()
        except (requests.RequestException, ValueError) as exc:
            last = exc
            time.sleep(6 * (attempt + 1))
    raise requests.RequestException(f"NVD unavailable: {last}")


def _vuln_to_item(vuln: dict) -> dict:
    rec = parse_nvd_cve(vuln.get("cve", {}))
    cve_id = rec["cve_id"]
    v3 = rec["cvss_v3"] or {}
    return {
        "id": f"nvd_{cve_id}", "platform": "nvd", "source": "nvd_api", "title": cve_id, "text": rec["description"],
        "author": "NVD/NIST", "timestamp": rec["published"], "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "cve_ids": [cve_id], "nvd_data": [rec], "nvd_status": "ok",
        "metadata": {"cve_id": cve_id, "cvss_score": v3.get("score"), "severity": v3.get("severity"),
                     "references": rec["references"][:5], "source_type": "nvd"},
    }


def _tracked_cves() -> set[str]:
    known: set[str] = set()
    for it in load_recent_raw(days=60):
        if it.get("platform") == "nvd":
            continue
        known |= {c.upper() for c in (it.get("cve_ids") or [])}
        known |= {c.upper() for c in _CVE_RE.findall(f"{it.get('title', '')} {(it.get('text') or '')[:1500]}")}
    return known


def run_once(force: bool = False) -> None:
    if not manager.gate("builtin-nvd", force):
        return
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=NVD_LOOKBACK_DAYS)
    try:
        known = _tracked_cves()
        vulns, index = [], 0
        for _ in range(MAX_PAGES):
            page = _fetch_page(start, end, index)
            vulns += page.get("vulnerabilities", [])
            index += PAGE_SIZE
            if index >= page.get("totalResults", 0):
                break
    except Exception as exc:
        manager.mark_fetch("builtin-nvd", success=False, error=str(exc))
        audit(EV_NVD_FETCH_FAIL, message=str(exc)[:300])
        logger.error("NVD fetch failed: %s", exc)
        return
    saved = 0
    for vuln in vulns:
        try:
            item = _vuln_to_item(vuln)
            cve = item["cve_ids"][0]
            score = (item["metadata"].get("cvss_score") or 0)
            if process(item, force=(cve in known or score >= CRITICAL_CVSS)):
                saved += 1
        except StorageError as exc:
            manager.mark_fetch("builtin-nvd", success=False, error=f"storage error: {exc}")
            audit(EV_NVD_FETCH_FAIL, message=f"storage error: {exc}"[:300])
            logger.error("NVD: storage error, collection aborted: %s", exc)
            return
        except Exception as exc:
            logger.error("NVD record skipped: %s", exc)
    manager.mark_fetch("builtin-nvd", success=True, item_count=len(vulns), new_items=saved)
    logger.info("NVD — %d CVEs fetched, %d saved (%d tracked CVEs linked)", len(vulns), saved, len(known))


def run_continuous() -> None:
    logger.info("NVD collector started (interval comes from the Source Manager)")
    while True:
        try:
            run_once()
        except Exception as exc:
            logger.error("NVD cycle error: %s", exc)
        time.sleep(TICK_SECONDS)
