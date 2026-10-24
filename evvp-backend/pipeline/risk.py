"""Risk, zero-day confidence and explainability engine.

Every score is the sum of named components, so the dashboard can show *why* a
finding scored what it did ("black-box" scores are never returned).

Matching uses word boundaries: the term "rce" must not match "source" or "force".
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from functools import lru_cache

from config.settings import TRUST_WEIGHT

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)

ACTIVE = ("actively exploited", "exploited in the wild", "exploitation in the wild", "in the wild",
          "active exploitation", "actively exploiting", "under active attack", "under attack",
          "under active exploitation", "mass exploitation", "being exploited")
ZERO = ("zero-day", "zero day", "0day", "0-day")
UNPATCHED = ("unpatched", "no patch available", "no fix available", "no patch yet")
EXPLOIT = ("exploit", "exploits", "poc", "proof of concept", "proof-of-concept", "exploit code",
           "shellcode", "weaponized", "working exploit")

# term -> (technique id, name). Only unambiguous, evidence-bearing terms are mapped.
ATTACK_MAP = {
    "remote code execution": ("T1190", "Exploit Public-Facing Application"),
    "rce": ("T1190", "Exploit Public-Facing Application"),
    "sql injection": ("T1190", "Exploit Public-Facing Application"),
    "deserialization": ("T1190", "Exploit Public-Facing Application"),
    "ssrf": ("T1190", "Exploit Public-Facing Application"),
    "privilege escalation": ("T1068", "Exploitation for Privilege Escalation"),
    "lpe": ("T1068", "Exploitation for Privilege Escalation"),
    "command injection": ("T1059", "Command and Scripting Interpreter"),
    "powershell": ("T1059.001", "PowerShell"),
    "phishing": ("T1566", "Phishing"),
    "credential theft": ("T1003", "OS Credential Dumping"),
    "credential dumping": ("T1003", "OS Credential Dumping"),
    "supply chain": ("T1195", "Supply Chain Compromise"),
    "authentication bypass": ("T1078", "Valid Accounts"),
    "auth bypass": ("T1078", "Valid Accounts"),
    "container escape": ("T1611", "Escape to Host"),
}


@lru_cache(maxsize=512)
def _pattern(term: str) -> re.Pattern:
    return re.compile(r"(?<![a-z0-9])" + re.escape(term) + r"(?![a-z0-9])")


def has_term(text: str, terms) -> str | None:
    """Return the first term found in ``text`` on word boundaries, else None."""
    text = (text or "").lower()
    for t in terms:
        if _pattern(t).search(text):
            return t
    return None


def _text(item: dict) -> str:
    return f"{item.get('title', '')} {item.get('text', '')} {item.get('summary', '')}".lower()


def trust_weight(item: dict) -> int:
    w = item.get("source_trust_weight")
    if isinstance(w, (int, float)) and w:
        return int(w)
    return TRUST_WEIGHT.get(item.get("source_trust") or "medium", TRUST_WEIGHT["medium"])


# ── facts ─────────────────────────────────────────────────────────────────────
def active_exploitation(item: dict) -> bool:
    return bool(item.get("kev")) or has_term(_text(item), ACTIVE) is not None


def poc_available(item: dict) -> bool:
    return has_term(_text(item), EXPLOIT) is not None


def cvss_of(item: dict) -> float | None:
    best = None
    for rec in item.get("nvd_data") or []:
        s = (rec.get("cvss_v3") or {}).get("score") or (rec.get("cvss_v2") or {}).get("score")
        try:
            s = float(s)
        except (TypeError, ValueError):
            continue
        best = s if best is None else max(best, s)
    return best


def severity_from_cvss(score: float) -> str:
    return "CRITICAL" if score >= 9.0 else "HIGH" if score >= 7.0 else "MEDIUM" if score >= 4.0 else "LOW"


def severity_from_risk(risk: int) -> str:
    return "CRITICAL" if risk >= 80 else "HIGH" if risk >= 60 else "MEDIUM" if risk >= 40 else "LOW"


def attack_techniques(item: dict) -> list[dict]:
    text = _text(item)
    found: dict[str, dict] = {}
    for term, (tid, name) in ATTACK_MAP.items():
        if _pattern(term).search(text):
            found.setdefault(tid, {"id": tid, "name": name, "matched": term})
    return list(found.values())


# ── zero-day confidence ───────────────────────────────────────────────────────
def zero_day_score(item: dict, cross_source_count: int = 1) -> tuple[int, list[str]]:
    """Confidence (0-100) that this is a *potential* zero-day. Never a certainty."""
    text = _text(item)
    score, ev = 0, []
    cves = item.get("cve_ids") or _CVE_RE.findall(text)
    if not cves:
        score += 20; ev.append("No CVE identifier found (+20)")
    if has_term(text, ZERO):
        score += 20; ev.append("Zero-day terminology detected (+20)")
    elif has_term(text, UNPATCHED):
        score += 8; ev.append("Unpatched / no-fix language detected (+8)")
    if active_exploitation(item):
        score += 20; ev.append("Exploitation evidence detected (+20)")
    if poc_available(item):
        score += 15; ev.append("Exploit/PoC evidence detected (+15)")
    if cross_source_count >= 3:
        score += 15; ev.append(f"Corroborated by {cross_source_count} independent sources (+15)")
    elif cross_source_count == 2:
        score += 8; ev.append("Corroborated by 2 independent sources (+8)")
    if trust_weight(item) >= 80:
        score += 10; ev.append("High-trust source (+10)")
    if item.get("nvd_data"):
        score = max(0, score - 10); ev.append("NVD record exists; zero-day confidence reduced (-10)")
    return max(0, min(score, 100)), ev


# ── risk ──────────────────────────────────────────────────────────────────────
def risk_breakdown(item: dict, cross_source_count: int = 1) -> list[dict]:
    """Named score components; their sum (capped at 100) is the risk score."""
    parts: list[dict] = []

    def add(factor: str, detail: str, points: float) -> None:
        if round(points) > 0:
            parts.append({"factor": factor, "detail": detail, "points": round(points)})

    sig = float(item.get("signal_score") or 0)
    add("Security signal strength", f"signal score {sig:g} (capped at 30)", min(sig, 30) / 30 * 20)
    cvss = cvss_of(item)
    if cvss:
        add("CVSS", f"base score {cvss:.1f}/10", cvss / 10 * 30)
    epss = item.get("epss")
    if epss is not None:
        e = max(0.0, min(float(epss), 1.0))
        add("EPSS", f"{e * 100:.2f}% probability of exploitation", e * 25)
    if item.get("kev"):
        add("CISA KEV", "listed in CISA Known Exploited Vulnerabilities", 15)
    elif has_term(_text(item), ACTIVE):
        add("Active exploitation", "exploitation reported in the wild", 15)
    elif poc_available(item):
        add("Exploit / PoC", "exploit or proof-of-concept evidence", 8)
    if cross_source_count >= 3:
        add("Cross-source confirmation", f"{cross_source_count} independent sources", 5)
    elif cross_source_count == 2:
        add("Cross-source confirmation", "2 independent sources", 3)
    zd, _ = zero_day_score(item, cross_source_count)
    if not item.get("cve_ids") and zd >= 60:
        add("Zero-day indicators", f"confidence {zd}/100", 5)
    tw = trust_weight(item)
    add("Source trust", f"{item.get('source_trust') or 'medium'} (weight {tw}/100)", tw / 100 * 8)
    return parts


def risk_score(item: dict, cross_source_count: int = 1) -> tuple[int, list[str]]:
    parts = risk_breakdown(item, cross_source_count)
    total = max(0, min(sum(p["points"] for p in parts), 100))
    return total, [f"{p['factor']}: {p['detail']} (+{p['points']})" for p in parts]


def build_intelligence(item: dict, cross_source_count: int = 1) -> dict:
    zd, zd_ev = zero_day_score(item, cross_source_count)
    parts = risk_breakdown(item, cross_source_count)
    risk = max(0, min(sum(p["points"] for p in parts), 100))
    return {
        "risk_score": risk,
        "risk_breakdown": parts,
        "risk_reasons": [f"{p['factor']}: {p['detail']} (+{p['points']})" for p in parts],
        "zero_day_score": zd,
        "zero_day_evidence": zd_ev,
        "zero_day_candidate": (not item.get("cve_ids")) and zd >= 45,
        "attack_techniques": attack_techniques(item),
        "cross_source_count": cross_source_count,
        "scored_at": datetime.now(timezone.utc).isoformat(),
    }
