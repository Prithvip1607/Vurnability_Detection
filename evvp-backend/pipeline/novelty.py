"""
Novelty checker — determines if a collected item represents a NEW vulnerability
not already seen in the stored dataset.

Checks:
  1. Exact ID match (already stored)
  2. URL match (same article re-collected)
  3. CVE ID overlap with recently stored items
  4. Title similarity (fuzzy — catches reposts with slightly different titles)
"""
from __future__ import annotations
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timedelta

from config.settings import NOVELTY_LOOKBACK_DAYS
from storage.db import load_recent_raw

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


@dataclass
class NoveltyResult:
    is_novel:      bool
    reason:        str          # human-readable explanation
    duplicate_id:  str = ""     # ID of the existing item if duplicate


def _extract_cves(item: dict) -> set[str]:
    text = f"{item.get('title', '')} {item.get('text', '')[:1000]}"
    return {c.upper() for c in _CVE_RE.findall(text)}


def _normalize(text: str) -> str:
    """Lowercase, strip accents, collapse whitespace, remove punctuation."""
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    text = re.sub(r"[^\w\s]", " ", text.lower())
    return re.sub(r"\s+", " ", text).strip()


def _token_overlap(a: str, b: str) -> float:
    """Jaccard similarity on word tokens."""
    ta = set(_normalize(a).split())
    tb = set(_normalize(b).split())
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def check(item: dict, existing: list[dict] | None = None) -> NoveltyResult:
    """
    Check whether `item` is novel against `existing` items.
    If `existing` is None, loads from storage automatically.
    """
    if existing is None:
        existing = load_recent_raw(days=NOVELTY_LOOKBACK_DAYS)

    item_id  = item.get("id", "")
    item_url = item.get("url", "")
    item_cves = _extract_cves(item)
    item_title = item.get("title", "")

    for ex in existing:
        # 1. Exact ID
        if item_id and item_id == ex.get("id"):
            return NoveltyResult(False, "exact_id_match", ex["id"])

        # 2. URL match
        if item_url and item_url == ex.get("url"):
            return NoveltyResult(False, "url_match", ex.get("id", ""))

        # 3. CVE overlap — same CVE already stored
        if item_cves:
            ex_cves = _extract_cves(ex)
            overlap = item_cves & ex_cves
            if overlap:
                return NoveltyResult(
                    False,
                    f"cve_overlap:{','.join(sorted(overlap))}",
                    ex.get("id", ""),
                )

        # 4. Title similarity >= 85% — likely repost
        if item_title and ex.get("title"):
            sim = _token_overlap(item_title, ex["title"])
            if sim >= 0.85:
                return NoveltyResult(False, f"title_similarity:{sim:.2f}", ex.get("id", ""))

    return NoveltyResult(True, "novel")
