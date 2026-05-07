"""
Threat Intelligence Filtering Layer
====================================
Multi-stage pipeline:
  1. Positive signal extraction  (exploit / vuln indicators)
  2. Negative signal detection   (educational / career noise)
  3. Threat relevance scoring    (weighted heuristics)
  4. Category classification     (4 tiers)
  5. Threshold gate              (drop low-confidence items)

Output schema per item:
  signal_score      int
  category          str
  matched_signals   list[str]
  negative_signals  list[str]
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field

# ── Configurable thresholds ───────────────────────────────────────────────────
MIN_SIGNAL_SCORE        = 8    # items below this are dropped entirely
EXPLOIT_DEV_MIN_SCORE   = 6    # minimum to qualify as exploit-dev discussion
HIGH_CONF_MIN_SCORE     = 14   # minimum for high_confidence_vulnerability_signal

# ── Categories ────────────────────────────────────────────────────────────────
CAT_HIGH_CONF   = "high_confidence_vulnerability_signal"
CAT_EXPLOIT_DEV = "exploit_development_discussion"
CAT_EDUCATIONAL = "educational_tutorial_content"
CAT_GENERAL     = "general_cybersecurity_discussion"

# ── Positive signal terms (term -> score) ─────────────────────────────────────
POSITIVE_SIGNALS: dict[str, int] = {
    # Active exploitation — highest priority
    "actively exploited":        10,
    "exploited in the wild":     10,
    "exploit in the wild":       10,
    "mass exploitation":         10,
    "under active exploitation":  9,
    "in the wild":                6,

    # Zero-day indicators
    "0day":                       9,
    "zero-day":                   9,
    "zero day":                   9,
    "unpatched vulnerability":    8,
    "no patch available":         8,
    "no fix available":           8,

    # RCE family
    "unauthenticated rce":        9,
    "unauth rce":                 9,
    "pre-auth rce":               9,
    "remote code execution":      8,
    "rce":                        7,

    # Auth / access control
    "auth bypass":                8,
    "authentication bypass":      8,
    "authorization bypass":       7,
    "unauthenticated":            4,
    "unauthorized access":        4,
    "broken access control":      5,

    # Memory corruption
    "use-after-free":             8,
    "heap overflow":              8,
    "heap spray":                 7,
    "stack overflow":             6,
    "buffer overflow":            6,
    "memory corruption":          8,
    "out-of-bounds write":        7,
    "out-of-bounds read":         6,
    "type confusion":             7,
    "integer overflow":           5,
    "double free":                7,
    "null pointer dereference":   5,
    "race condition":             5,

    # Privilege / escape
    "privilege escalation":       7,
    "local privilege escalation": 7,
    "lpe":                        6,
    "sandbox escape":             9,
    "container escape":           9,
    "kernel exploit":             9,
    "kernel vulnerability":       8,
    "ring0":                      7,
    "eop":                        6,

    # PoC / exploit release
    "poc":                        6,
    "proof of concept":           6,
    "proof-of-concept":           6,
    "exploit released":           9,
    "exploit available":          8,
    "working exploit":            9,
    "functional exploit":         9,
    "exploit chain":              8,
    "exploit code":               7,
    "exploit published":          8,

    # Exploit development
    "shellcode":                  7,
    "rop chain":                  7,
    "return oriented programming":7,
    "heap grooming":              7,
    "heap feng shui":             7,
    "exploit development":        6,
    "exploit writing":            6,
    "exploit technique":          6,
    "bypass mitigation":          7,
    "aslr bypass":                7,
    "dep bypass":                 7,
    "cfg bypass":                 7,

    # Disclosure
    "vulnerability disclosure":   6,
    "full disclosure":            6,
    "responsible disclosure":     5,
    "patch bypass":               8,
    "incomplete fix":             7,
    "emergency patch":            7,
    "out-of-band patch":          7,
    "critical vulnerability":     6,

    # Code execution
    "arbitrary code execution":   8,
    "code execution":             6,
    "command injection":          6,
    "deserialization":            6,
    "xxe":                        5,
    "ssrf":                       5,
    "sql injection":              4,
    "path traversal":             4,

    # Suspicious supply chain
    "backdoor":                   7,
    "malicious package":          7,
    "supply chain attack":        7,
    "typosquatting":              6,
    "implant":                    6,
}

# ── Negative signal terms (term -> penalty) ───────────────────────────────────
NEGATIVE_SIGNALS: dict[str, int] = {
    # Career / learning noise
    "how to learn":              10,
    "how do i learn":            10,
    "where to start":             9,
    "getting started":            8,
    "i want to learn":            9,
    "i wanna learn":              9,
    "i am new":                   8,
    "i'm new":                    8,
    "newbie":                     8,
    "beginner":                   7,
    "noob":                       7,
    "starting out":               7,
    "learning path":              8,
    "roadmap":                    8,
    "study guide":                8,
    "learning resources":         8,
    "resources to learn":         8,
    "mentorship":                 9,
    "mentor":                     7,
    "career":                     7,
    "job":                        5,
    "interview":                  7,
    "certification":              7,
    "oscp":                       5,
    "ceh":                        6,
    "ejpt":                       6,

    # Tutorial / educational
    "tutorial":                   8,
    "course":                     7,
    "udemy":                      8,
    "tryhackme":                  7,
    "hackthebox":                 5,
    "ctf":                        5,
    "ctf writeup":                6,
    "write-up":                   4,
    "walkthrough":                6,
    "lab":                        4,

    # Generic tool noise
    "port scanner":               7,
    "subdomain scanner":          7,
    "recon tool":                 7,
    "recon framework":            7,
    "pentest tool":               6,
    "pentest framework":          6,
    "awesome list":               8,
    "cheatsheet":                 6,
    "cheat sheet":                6,
    "wordlist":                   7,
    "password list":              7,

    # Dependency / CI noise
    "dependabot":                 9,
    "dependency update":          9,
    "bump version":               9,
    "version bump":               9,
    "chore:":                     8,
    "docs:":                      8,
    "ci:":                        8,
    "build:":                     7,
    "refactor:":                  7,
}

# ── Known noise repos (exact match on title) ──────────────────────────────────
NOISE_REPOS: set[str] = {
    "projectdiscovery/httpx", "projectdiscovery/subfinder",
    "projectdiscovery/naabu", "projectdiscovery/nuclei",
    "projectdiscovery/katana", "projectdiscovery/dnsx",
    "swisskyrepo/payloadsallthethings",
    "danielmiessler/seclists",
    "owasp/owasp-mstg", "owasp/wstg",
}

# ── Category keyword sets ─────────────────────────────────────────────────────
_HIGH_CONF_KEYWORDS = {
    "actively exploited", "exploited in the wild", "exploit in the wild",
    "0day", "zero-day", "zero day", "rce", "remote code execution",
    "unauthenticated rce", "auth bypass", "authentication bypass",
    "sandbox escape", "container escape", "kernel exploit",
    "exploit released", "exploit available", "working exploit",
    "poc", "proof of concept", "proof-of-concept",
    "arbitrary code execution", "memory corruption", "use-after-free",
    "heap overflow", "privilege escalation", "exploit chain",
}

_EXPLOIT_DEV_KEYWORDS = {
    "shellcode", "rop chain", "heap grooming", "heap feng shui",
    "exploit development", "exploit writing", "exploit technique",
    "aslr bypass", "dep bypass", "cfg bypass", "bypass mitigation",
    "return oriented programming", "heap spray", "type confusion",
    "buffer overflow", "stack overflow", "out-of-bounds",
    "integer overflow", "double free", "race condition",
}

_EDUCATIONAL_KEYWORDS = {
    "tutorial", "course", "beginner", "learning", "roadmap",
    "mentorship", "certification", "study guide", "getting started",
    "how to learn", "ctf", "tryhackme", "hackthebox", "walkthrough",
}

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class FilterResult:
    passes:          bool
    signal_score:    int
    category:        str
    matched_signals: list[str] = field(default_factory=list)
    negative_signals: list[str] = field(default_factory=list)


# ── Core scoring ──────────────────────────────────────────────────────────────

def _build_corpus(item: dict) -> str:
    return " ".join([
        (item.get("title") or ""),
        (item.get("text") or "")[:3000],
        str(item.get("metadata") or ""),
    ]).lower()


def _score_positive(corpus: str) -> tuple[int, list[str]]:
    total = 0
    matched = []
    for term, pts in POSITIVE_SIGNALS.items():
        if term in corpus:
            total += pts
            matched.append(term)

    # CVE bonus: each unique CVE = +4, capped at 12
    cves = list(set(_CVE_RE.findall(corpus)))
    if cves:
        total += min(len(cves) * 4, 12)
        matched.extend(cves[:3])

    return total, matched


def _score_negative(title: str, corpus: str) -> tuple[int, list[str]]:
    total = 0
    matched = []

    # Title penalties are doubled (title is the strongest signal)
    for term, pts in NEGATIVE_SIGNALS.items():
        if term in title.lower():
            total += pts * 2
            matched.append(term)
        elif term in corpus:
            total += pts

    # Known noise repo
    repo = title.lower()
    if any(nr in repo for nr in NOISE_REPOS):
        total += 15

    return total, matched


def _classify(pos_score: int, neg_score: int,
               matched: list[str], neg_matched: list[str]) -> str:
    matched_set = set(m.lower() for m in matched)

    # Educational check first — if heavy negative signals dominate, classify as noise
    if neg_score >= 10 and pos_score < HIGH_CONF_MIN_SCORE:
        if any(k in matched_set for k in _EDUCATIONAL_KEYWORDS):
            return CAT_EDUCATIONAL
        return CAT_GENERAL

    # High confidence: strong exploit/vuln indicators
    if pos_score >= HIGH_CONF_MIN_SCORE and matched_set & _HIGH_CONF_KEYWORDS:
        return CAT_HIGH_CONF

    # Exploit development: technical but not necessarily active exploitation
    if pos_score >= EXPLOIT_DEV_MIN_SCORE and matched_set & _EXPLOIT_DEV_KEYWORDS:
        return CAT_EXPLOIT_DEV

    # Educational content with some security terms
    if any(k in matched_set for k in _EDUCATIONAL_KEYWORDS):
        return CAT_EDUCATIONAL

    return CAT_GENERAL


# ── Public API ────────────────────────────────────────────────────────────────

def analyze(item: dict) -> FilterResult:
    """
    Full multi-stage analysis of a raw collected item.
    Returns a FilterResult with score, category, signals, and pass/fail.
    """
    corpus = _build_corpus(item)
    title  = item.get("title") or ""

    pos_score, matched    = _score_positive(corpus)
    neg_score, neg_matched = _score_negative(title, corpus)
    net_score = max(pos_score - neg_score, 0)

    category = _classify(pos_score, neg_score, matched, neg_matched)

    # Only pass high_confidence and exploit_dev categories above threshold
    passes = (
        net_score >= MIN_SIGNAL_SCORE
        and category in (CAT_HIGH_CONF, CAT_EXPLOIT_DEV)
    )

    return FilterResult(
        passes=passes,
        signal_score=net_score,
        category=category,
        matched_signals=matched,
        negative_signals=neg_matched,
    )


def is_signal(item: dict) -> tuple[bool, int, list[str]]:
    """
    Backward-compatible wrapper used by all collectors.
    Returns (passes, signal_score, matched_signals).
    """
    result = analyze(item)
    return result.passes, result.signal_score, result.matched_signals
