"""
Novelty checker — determines if a collected item represents a NEW vulnerability
not already seen in the stored dataset.

Checks:
  1. Exact ID match (already stored)
  2. URL match (same article re-collected)
  3. CVE ID overlap with recently stored items
  4. Title similarity >= 0.72 (fuzzy — catches reposts with slightly different titles)
  5. Keyword fingerprint — same platform + same top exploit keywords = same story
"""
from __future__ import annotations
import re
import unicodedata
from dataclasses import dataclass

from config.settings import NOVELTY_LOOKBACK_DAYS
from storage.db import load_recent_raw

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

# High-signal terms used to fingerprint a vulnerability story
_FINGERPRINT_TERMS = [
    "zero-day", "0day", "rce", "remote code execution", "unauthenticated",
    "auth bypass", "privilege escalation", "sandbox escape", "kernel exploit",
    "use-after-free", "heap overflow", "memory corruption", "poc",
    "proof of concept", "exploit released", "actively exploited",
    "exploited in the wild", "working exploit", "container escape",
]


@dataclass
class NoveltyResult:
    is_novel:      bool
    reason:        str
    duplicate_id:  str = ""


def _extract_cves(item: dict) -> set[str]:
    text = f"{item.get('title', '')} {item.get('text', '')[:1000]}"
    return {c.upper() for c in _CVE_RE.findall(text)}


def _normalize(text: str) -> str:
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    text = re.sub(r"[^\w\s]", " ", text.lower())
    return re.sub(r"\s+", " ", text).strip()


def _token_overlap(a: str, b: str) -> float:
    ta = set(_normalize(a).split())
    tb = set(_normalize(b).split())
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def _keyword_fingerprint(item: dict) -> frozenset[str]:
    """Extract which high-signal terms appear in title+text."""
    text = _normalize(f"{item.get('title', '')} {item.get('text', '')[:500]}")
    return frozenset(t for t in _FINGERPRINT_TERMS if t in text)


def check(item: dict, existing: list[dict] | None = None) -> NoveltyResult:
    if existing is None:
        existing = load_recent_raw(days=NOVELTY_LOOKBACK_DAYS)

    item_id    = item.get("id", "")
    item_url   = item.get("url", "")
    item_cves  = _extract_cves(item)
    item_title = item.get("title", "")
    item_fp    = _keyword_fingerprint(item)

    for ex in existing:
        # 1. Exact ID
        if item_id and item_id == ex.get("id"):
            return NoveltyResult(False, "exact_id_match", ex["id"])

        # 2. URL match
        if item_url and item_url == ex.get("url"):
            return NoveltyResult(False, "url_match", ex.get("id", ""))

        # 3. CVE overlap
        if item_cves:
            ex_cves = _extract_cves(ex)
            overlap = item_cves & ex_cves
            if overlap:
                return NoveltyResult(
                    False,
                    f"cve_overlap:{','.join(sorted(overlap))}",
                    ex.get("id", ""),
                )

        # 4. Title similarity >= 0.72
        if item_title and ex.get("title"):
            sim = _token_overlap(item_title, ex["title"])
            if sim >= 0.72:
                return NoveltyResult(False, f"title_similarity:{sim:.2f}", ex.get("id", ""))

        # 5. Keyword fingerprint — same 3+ exploit terms = same story, different source
        if len(item_fp) >= 3:
            ex_fp = _keyword_fingerprint(ex)
            common = item_fp & ex_fp
            if len(common) >= 3:
                return NoveltyResult(
                    False,
                    f"keyword_fingerprint:{','.join(sorted(common)[:3])}",
                    ex.get("id", ""),
                )

    return NoveltyResult(True, "novel")
