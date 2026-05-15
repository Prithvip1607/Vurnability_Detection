"""
Phase 3 — Verification Engine

Runs after novelty check on every novel item. Produces a verification record:
  - poc_found          : bool   — GitHub repo with actual exploit code detected
  - poc_signals        : list   — what was found (file types, keywords, stars)
  - affected_products  : list   — vendor/product/version extracted from text
  - credibility_score  : int    — 0-100 composite score
  - credibility_notes  : list   — human-readable reasons
  - in_nvd             : bool   — CVE exists in NVD
  - in_nvd_at          : str    — when it was published in NVD
  - cross_source_count : int    — how many distinct sources mention this vuln
  - verification_status: str    — confirmed / likely / unverified / noise
"""
from __future__ import annotations
import re
from datetime import datetime, timezone

import requests

from utils.logger import get_logger

logger = get_logger("verifier")

_CVE_RE    = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
_GITHUB_RE = re.compile(r"github\.com/([^/\s\"']+/[^/\s\"']+)", re.IGNORECASE)

# Source reputation weights (higher = more credible)
_SOURCE_REPUTATION: dict[str, int] = {
    "googleprojectzero": 40,
    "github_org_googleprojectzero": 40,
    "portswigger": 30,
    "unit42": 25,
    "bleepingcomputer": 20,
    "thehackernews": 18,
    "securityweek": 18,
    "krebsonsecurity": 20,
    "microsoft": 22,
    "nvd_api": 35,
    "github_repos": 15,
    "github_issues": 12,
    "github_commits": 10,
    "r/netsec": 18,
    "r/exploitdev": 15,
    "r/blueteamsec": 15,
}

# PoC file extensions that indicate real exploit code
_POC_EXTENSIONS = {".py", ".c", ".cpp", ".rb", ".go", ".rs", ".sh", ".ps1", ".js", ".java"}

# Keywords in repo description/README that indicate PoC
_POC_KEYWORDS = {
    "exploit", "poc", "proof of concept", "proof-of-concept",
    "rce", "lpe", "privilege escalation", "remote code execution",
    "shellcode", "payload", "bypass", "vulnerability",
}

# Product/vendor extraction patterns
_PRODUCT_PATTERNS = [
    re.compile(r"\b(CVE-\d{4}-\d+)\b", re.IGNORECASE),
    re.compile(r"\b(Windows\s+\d+(?:\s+\w+)?)\b", re.IGNORECASE),
    re.compile(r"\b(Linux\s+kernel\s+[\d.]+)\b", re.IGNORECASE),
    re.compile(r"\b(Apache\s+\w+(?:\s+[\d.]+)?)\b", re.IGNORECASE),
    re.compile(r"\b(nginx\s+[\d.]+)\b", re.IGNORECASE),
    re.compile(r"\b(OpenSSL\s+[\d.]+)\b", re.IGNORECASE),
    re.compile(r"\b(Chrome\s+[\d.]+)\b", re.IGNORECASE),
    re.compile(r"\b(Firefox\s+[\d.]+)\b", re.IGNORECASE),
    re.compile(r"\b(VMware\s+\w+(?:\s+[\d.]+)?)\b", re.IGNORECASE),
    re.compile(r"\b(Cisco\s+\w+(?:\s+[\d.]+)?)\b", re.IGNORECASE),
    re.compile(r"\b(Palo\s+Alto\s+\w+)\b", re.IGNORECASE),
    re.compile(r"\b(Fortinet\s+\w+)\b", re.IGNORECASE),
    re.compile(r"\b(Ivanti\s+\w+)\b", re.IGNORECASE),
    re.compile(r"\b(Confluence\s+[\d.]+)\b", re.IGNORECASE),
    re.compile(r"\b(Jira\s+[\d.]+)\b", re.IGNORECASE),
    re.compile(r"\b(Exchange\s+Server\s+[\d.]+)\b", re.IGNORECASE),
    re.compile(r"\b(SharePoint\s+[\d.]+)\b", re.IGNORECASE),
    re.compile(r"\b(Spring\s+\w+\s+[\d.]+)\b", re.IGNORECASE),
    re.compile(r"\b(Log4j\s+[\d.]+)\b", re.IGNORECASE),
    re.compile(r"\b(Kubernetes\s+[\d.]+)\b", re.IGNORECASE),
    re.compile(r"\b(Docker\s+[\d.]+)\b", re.IGNORECASE),
]


def verify(item: dict, cross_source_count: int = 1) -> dict:
    """
    Run full verification on a novel item.
    Returns a verification record dict.
    """
    text  = f"{item.get('title', '')} {item.get('text', '')[:3000]}"
    url   = item.get("url", "")
    src   = item.get("source", "")
    score = item.get("signal_score", 0)

    poc_found, poc_signals = _check_poc(url, text)
    affected_products      = _extract_products(text)
    cred_score, cred_notes = _credibility_score(
        item, poc_found, cross_source_count, score
    )
    in_nvd, in_nvd_at      = _check_nvd_status(item)
    status                 = _determine_status(cred_score, poc_found, in_nvd, score)

    return {
        "raw_id":             item.get("id", ""),
        "poc_found":          poc_found,
        "poc_signals":        poc_signals,
        "affected_products":  affected_products,
        "credibility_score":  cred_score,
        "credibility_notes":  cred_notes,
        "in_nvd":             in_nvd,
        "in_nvd_at":          in_nvd_at,
        "cross_source_count": cross_source_count,
        "verification_status": status,
        "verified_at":        datetime.now(timezone.utc).isoformat(),
    }


# ── PoC detection ─────────────────────────────────────────────────────────────

def _check_poc(url: str, text: str) -> tuple[bool, list[str]]:
    signals: list[str] = []

    # Check if URL is a GitHub repo
    gh_match = _GITHUB_RE.search(url) or _GITHUB_RE.search(text)
    if gh_match:
        repo = gh_match.group(1).rstrip("/")
        found, repo_signals = _inspect_github_repo(repo)
        signals.extend(repo_signals)
        if found:
            return True, signals

    # Text-based PoC signals
    text_lower = text.lower()
    for kw in _POC_KEYWORDS:
        if kw in text_lower:
            signals.append(f"keyword:{kw}")

    poc_in_text = any(s.startswith("keyword:") for s in signals)
    return poc_in_text, signals


def _inspect_github_repo(repo: str) -> tuple[bool, list[str]]:
    """Check a GitHub repo for actual exploit code."""
    signals: list[str] = []
    try:
        from config.settings import GITHUB_TOKEN
        headers = {"Accept": "application/vnd.github+json"}
        if GITHUB_TOKEN:
            headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

        # Get repo metadata
        r = requests.get(
            f"https://api.github.com/repos/{repo}",
            headers=headers, timeout=10
        )
        if r.status_code != 200:
            return False, signals

        data = r.json()
        stars = data.get("stargazers_count", 0)
        desc  = (data.get("description") or "").lower()
        lang  = data.get("language", "")

        if stars >= 10:
            signals.append(f"stars:{stars}")
        if lang:
            signals.append(f"language:{lang}")

        # Check description for PoC keywords
        for kw in _POC_KEYWORDS:
            if kw in desc:
                signals.append(f"desc:{kw}")
                break

        # Get file tree (top level)
        r2 = requests.get(
            f"https://api.github.com/repos/{repo}/contents",
            headers=headers, timeout=10
        )
        if r2.status_code == 200:
            files = r2.json()
            if isinstance(files, list):
                for f in files:
                    name = f.get("name", "").lower()
                    ext  = "." + name.rsplit(".", 1)[-1] if "." in name else ""
                    if ext in _POC_EXTENSIONS:
                        signals.append(f"file:{name}")
                    if any(kw in name for kw in ("exploit", "poc", "payload", "shellcode")):
                        signals.append(f"filename:{name}")

        has_code = any(s.startswith("file:") or s.startswith("filename:") for s in signals)
        return has_code, signals

    except Exception as e:
        logger.debug("GitHub repo inspect failed for %s: %s", repo, e)
        return False, signals


# ── Product extraction ────────────────────────────────────────────────────────

def _extract_products(text: str) -> list[str]:
    found: set[str] = set()
    for pattern in _PRODUCT_PATTERNS:
        for m in pattern.findall(text):
            val = m.strip() if isinstance(m, str) else m[0].strip()
            if val and len(val) > 3:
                found.add(val)
    return sorted(found)[:10]


# ── Credibility scoring ───────────────────────────────────────────────────────

def _credibility_score(
    item: dict, poc_found: bool, cross_sources: int, signal_score: int
) -> tuple[int, list[str]]:
    score = 0
    notes: list[str] = []

    # Source reputation
    src = item.get("source", "").lower()
    for key, pts in _SOURCE_REPUTATION.items():
        if key in src:
            score += pts
            notes.append(f"trusted source: {key} (+{pts})")
            break
    else:
        score += 5
        notes.append("unknown source (+5)")

    # Signal score contribution
    sig_pts = min(signal_score * 2, 30)
    score  += sig_pts
    notes.append(f"signal score {signal_score} (+{sig_pts})")

    # PoC found
    if poc_found:
        score += 25
        notes.append("PoC/exploit code found (+25)")

    # Cross-source confirmation
    if cross_sources >= 3:
        score += 20
        notes.append(f"confirmed on {cross_sources} sources (+20)")
    elif cross_sources == 2:
        score += 10
        notes.append(f"seen on {cross_sources} sources (+10)")

    # NVD data attached
    if item.get("nvd_data"):
        score += 15
        notes.append("NVD record found (+15)")

    # CVE IDs present
    if item.get("cve_ids"):
        score += 10
        notes.append(f"CVE IDs: {item['cve_ids'][:3]} (+10)")

    return min(score, 100), notes


# ── NVD status ────────────────────────────────────────────────────────────────

def _check_nvd_status(item: dict) -> tuple[bool, str]:
    """Check if any CVE in this item is already in NVD."""
    nvd_data = item.get("nvd_data", [])
    if nvd_data:
        published = nvd_data[0].get("published", "")
        return True, published

    # Check from matched signals (CVE IDs extracted during scoring)
    cve_ids = item.get("cve_ids", [])
    if not cve_ids:
        text = f"{item.get('title', '')} {item.get('text', '')[:500]}"
        cve_ids = list(set(_CVE_RE.findall(text)))

    return bool(cve_ids and nvd_data), ""


# ── Status determination ──────────────────────────────────────────────────────

def _determine_status(cred_score: int, poc_found: bool, in_nvd: bool, signal_score: int) -> str:
    if cred_score >= 70 and (poc_found or in_nvd):
        return "confirmed"
    if cred_score >= 45 or (poc_found and signal_score >= 14):
        return "likely"
    if signal_score >= 8:
        return "unverified"
    return "noise"
