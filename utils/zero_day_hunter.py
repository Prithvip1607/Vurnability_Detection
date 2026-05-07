"""
Vulnerability Hunter - finds both zero-days (no CVE) and CVE-tagged posts.

Modes:
- Zero-day : recent posts with NO CVE references (pre-disclosure)
- CVE      : recent posts WITH CVE IDs (already disclosed, still high-signal)
"""
import json
import os
import re
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import RAW_DATA_DIR

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_ts(ts_str: str) -> datetime | None:
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except:
        return None


def _is_recent(item: dict, days: int) -> bool:
    dt = _parse_ts(item.get("collected_at") or item.get("timestamp", ""))
    if not dt:
        return False
    return dt.replace(tzinfo=None) > datetime.now() - timedelta(days=days)


def _extract_cves(item: dict) -> list[str]:
    text = f"{item.get('title','')} {item.get('text','')[:1000]}"
    return list(set(_CVE_RE.findall(text)))


def _has_cve(item: dict) -> bool:
    return bool(_extract_cves(item))


def _zero_day_score(item: dict) -> int:
    score = item.get("signal_score", 0)
    matched = [s.lower() for s in item.get("matched_signals", [])]

    if any(x in matched for x in ["0day", "zero-day", "zero day"]):
        score += 10
    if any(x in matched for x in ["actively exploited", "exploit in the wild", "exploited in the wild"]):
        score += 8
    if "poc" in matched or "proof of concept" in matched or "proof-of-concept" in matched:
        score += 5
    if any(x in matched for x in ["unauthenticated rce", "unauth rce", "pre-auth rce"]):
        score += 6
    if _is_recent(item, days=2):
        score += 5

    return score


# ── Core loader ───────────────────────────────────────────────────────────────

def _load_all(days: int) -> list[dict]:
    items = []
    for platform in ["reddit", "github", "blog"]:
        platform_dir = os.path.join(RAW_DATA_DIR, platform)
        if not os.path.exists(platform_dir):
            continue
        for filename in os.listdir(platform_dir):
            if not filename.endswith(".jsonl"):
                continue
            try:
                with open(os.path.join(platform_dir, filename), "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            item = json.loads(line)
                            if _is_recent(item, days):
                                items.append(item)
            except Exception as e:
                print(f"Error reading {filename}: {e}")
    return items


def _dedupe(items: list[dict]) -> list[dict]:
    seen: set[str] = set()
    out = []
    for item in items:
        url = item.get("url", "")
        if url and url in seen:
            continue
        seen.add(url)
        out.append(item)
    return out


# ── Public hunt functions ─────────────────────────────────────────────────────

def hunt_zero_days(days: int = 7, min_score: int = 10, limit: int = 50) -> list[dict]:
    """Items with NO CVE ID - pre-disclosure / unverified vulnerabilities."""
    candidates = []
    for item in _load_all(days):
        if _has_cve(item):
            continue
        score = _zero_day_score(item)
        if score >= min_score:
            item["zero_day_score"] = score
            candidates.append(item)

    candidates.sort(key=lambda x: x["zero_day_score"], reverse=True)
    return _dedupe(candidates)[:limit]


def hunt_cve_vulns(days: int = 7, min_score: int = 6, limit: int = 50) -> list[dict]:
    """Items WITH CVE IDs - disclosed vulnerabilities being actively discussed."""
    candidates = []
    for item in _load_all(days):
        cves = _extract_cves(item)
        if not cves:
            continue
        score = item.get("signal_score", 0)
        if score >= min_score:
            item["cve_ids"] = cves
            candidates.append(item)

    candidates.sort(key=lambda x: x.get("signal_score", 0), reverse=True)
    return _dedupe(candidates)[:limit]


# ── Print helpers ─────────────────────────────────────────────────────────────

def _safe(text: str) -> str:
    """Strip non-cp1252 characters for Windows console output."""
    return text.encode("cp1252", errors="replace").decode("cp1252")


def print_zero_days(candidates: list[dict]) -> None:
    if not candidates:
        print("No zero-day candidates found.")
        return
    print("\n" + "="*80)
    print("  ZERO-DAY CANDIDATES - No CVE ID (pre-disclosure)")
    print("="*80 + "\n")
    for i, item in enumerate(candidates, 1):
        ts = (item.get("collected_at") or item.get("timestamp", ""))[:19]
        print(f"[{i}] Score: {item['zero_day_score']} | {item.get('platform','').upper()} | {ts}")
        print(f"    Title   : {_safe(item.get('title',''))}")
        print(f"    Signals : {_safe(', '.join(item.get('matched_signals', [])[:8]))}")
        print(f"    URL     : {item.get('url','')}")
        print()


def print_cve_vulns(candidates: list[dict]) -> None:
    if not candidates:
        print("No CVE vulnerabilities found.")
        return
    print("\n" + "="*80)
    print("  CVE-TAGGED VULNERABILITIES - Disclosed & Actively Discussed")
    print("="*80 + "\n")
    for i, item in enumerate(candidates, 1):
        ts = (item.get("collected_at") or item.get("timestamp", ""))[:19]
        cves = ", ".join(item.get("cve_ids", [])[:3])
        print(f"[{i}] Score: {item.get('signal_score',0)} | {item.get('platform','').upper()} | {ts}")
        print(f"    CVE(s)  : {cves}")
        print(f"    Title   : {_safe(item.get('title',''))}")
        print(f"    Signals : {_safe(', '.join(item.get('matched_signals', [])[:8]))}")
        print(f"    URL     : {item.get('url','')}")
        print()


# ── Export ────────────────────────────────────────────────────────────────────

def export_results(candidates: list[dict], filename: str) -> None:
    path = os.path.join(RAW_DATA_DIR, "..", filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(candidates, f, indent=2, ensure_ascii=False, default=str)
    print(f"Exported {len(candidates)} items -> {path}")


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mode      = sys.argv[1] if len(sys.argv) > 1 else "both"   # zeroday | cve | both
    days      = int(sys.argv[2]) if len(sys.argv) > 2 else 7
    min_score = int(sys.argv[3]) if len(sys.argv) > 3 else 10
    limit     = int(sys.argv[4]) if len(sys.argv) > 4 else 50

    if mode in ("zeroday", "both"):
        results = hunt_zero_days(days=days, min_score=min_score, limit=limit)
        print_zero_days(results)
        if results:
            export_results(results, "zero_day_candidates.json")

    if mode in ("cve", "both"):
        results = hunt_cve_vulns(days=days, min_score=min_score, limit=limit)
        print_cve_vulns(results)
        if results:
            export_results(results, "cve_vulnerabilities.json")
