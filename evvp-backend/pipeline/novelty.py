"""
Novelty checker — determines if a collected item represents a NEW vulnerability
not already seen in the stored dataset.

Checks:
  1. Exact ID match (already stored)
  2. URL match (same article re-collected)
  3. CVE ID overlap with recently stored items
  4. Title similarity >= 0.72 (fuzzy — catches reposts with slightly different titles)
  5. Distinctive-token match — same product/codename words (generic terms like "RCE" never merge)
"""
from __future__ import annotations
import re
import unicodedata
from dataclasses import dataclass

from config.settings import NOVELTY_LOOKBACK_DAYS
from storage.db import load_recent_raw

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# Words that describe *any* vulnerability story and therefore never identify a specific one.
_GENERIC = {
    "vulnerability", "vulnerabilities", "exploit", "exploited", "exploits", "security", "remote", "code",
    "execution", "critical", "flaw", "flaws", "patch", "patches", "patched", "released", "release", "attack",
    "attacks", "attackers", "hackers", "actively", "researchers", "researcher", "update", "updates", "with",
    "from", "that", "this", "into", "after", "over", "using", "used", "have", "been", "their", "which", "could",
    "allow", "allows", "affecting", "impacting", "against", "about", "than", "more", "newly", "zero", "days",
    "dubbed", "shows", "gets", "unpatched", "bug", "bugs", "issue", "warns", "hits", "under", "unauthenticated",
    "authentication", "bypass", "privilege", "escalation", "injection",
    "wild", "exploitation", "exploiting", "public", "publicly", "available", "disclosed", "discloses", "disclosure", "vendor",
    "confirms", "confirmed", "reported", "reports", "reportedly", "software", "firmware", "version", "versions", "users",
    "servers", "devices", "appliances", "products", "product", "systems", "platform", "instances", "customers", "latest",
    "urgent", "advisory", "alert", "fixes", "fixed", "fixing", "arbitrary", "executes", "execute", "hits", "hit", "hijack",
    "takeover", "chain", "multiple", "several", "major", "serious", "severe", "high", "severity", "risk", "threat", "threats",
}
DISTINCT_MIN_SHARED = 2        # distinctive title tokens two reports must share to be the same story
DISTINCT_MIN_COVERAGE = 0.6    # ... covering at least this share of the shorter title


@dataclass
class NoveltyResult:
    is_novel:      bool
    reason:        str
    duplicate_id:  str = ""


def _extract_cves(item: dict) -> set[str]:
    text = f"{item.get('title', '')} {(item.get('text') or '')[:1000]}"
    return {c.upper() for c in _CVE_RE.findall(text)} | {c.upper() for c in (item.get("cve_ids") or [])}


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


def _distinct_tokens(title: str) -> set[str]:
    """Product / vendor / codename words in a title (generic vulnerability vocabulary removed)."""
    return {t for t in re.findall(r"[a-z0-9]{4,}", _normalize(title)) if t not in _GENERIC}


def _same_story(a_title: str, b_title: str) -> bool:
    """Two titles describe one story if they share >=2 distinctive tokens covering most of the shorter one.

    Sharing only generic terms ("RCE", "actively exploited") never merges unrelated stories.
    """
    ta, tb = _distinct_tokens(a_title), _distinct_tokens(b_title)
    shared = len(ta & tb)
    if shared < DISTINCT_MIN_SHARED:
        return False
    return shared / max(1, min(len(ta), len(tb))) >= DISTINCT_MIN_COVERAGE


def check(item: dict, existing: list[dict] | None = None) -> NoveltyResult:
    if existing is None:
        existing = load_recent_raw(days=NOVELTY_LOOKBACK_DAYS)

    item_id    = item.get("id", "")
    item_url   = item.get("url", "")
    item_cves  = _extract_cves(item)
    item_title = item.get("title", "")

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

        # 5. Same product/codename story reported with different wording
        if item_title and ex.get("title") and _same_story(item_title, ex["title"]):
            return NoveltyResult(False, "distinctive_title_match", ex.get("id", ""))

    return NoveltyResult(True, "novel")
