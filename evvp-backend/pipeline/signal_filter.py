"""
Signal scoring engine.
Scores a raw item on positive exploit/vuln indicators minus noise penalties.
Returns a FilterResult with score, category, matched terms, and pass/fail.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field

from config.settings import MIN_SIGNAL_SCORE, EXPLOIT_DEV_MIN_SCORE, HIGH_CONF_MIN_SCORE
from pipeline.risk import _pattern as _term_re   # word-boundary matcher shared with the risk engine

CAT_HIGH_CONF   = "high_confidence_vulnerability_signal"
CAT_EXPLOIT_DEV = "exploit_development_discussion"
CAT_EDUCATIONAL = "educational_tutorial_content"
CAT_GENERAL     = "general_cybersecurity_discussion"

POSITIVE_SIGNALS: dict[str, int] = {
    # Active exploitation
    "actively exploited":        10,
    "exploited in the wild":     10,
    "exploit in the wild":       10,
    "mass exploitation":         10,
    "under active exploitation":  9,
    "in the wild":                6,
    # Zero-day
    "0day":                       9,
    "0-day":                      9,
    "zero-day":                   9,
    "zero day":                   9,
    "unpatched vulnerability":    8,
    "no patch available":         8,
    "no fix available":           8,
    # RCE
    "unauthenticated rce":        9,
    "unauth rce":                 9,
    "pre-auth rce":               9,
    "remote code execution":      8,
    "rce":                        7,
    # Auth
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
    "use after free":             8,
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
    # Exploit dev
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
    "server-side request forgery":6,
    "xml external entity":        5,
    # Supply chain
    "backdoor":                   7,
    "malicious package":          7,
    "supply chain attack":        7,
    "typosquatting":              6,
    "implant":                    6,
    "dependency confusion":       7,
}

NEGATIVE_SIGNALS: dict[str, int] = {
    "how to learn":    10, "how do i learn": 10, "where to start": 9,
    "getting started":  8, "i want to learn": 9, "i wanna learn":  9,
    "i am new":         8, "i'm new":         8, "newbie":          8,
    "beginner":         7, "noob":            7, "starting out":    7,
    "learning path":    8, "roadmap":         8, "study guide":     8,
    "learning resources":8,"resources to learn":8,"mentorship":     9,
    "mentor":           7, "career":          7, "job":             5,
    "interview":        7, "certification":   7, "oscp":            5,
    "ceh":              6, "ejpt":            6,
    "tutorial":         8, "course":          7, "udemy":           8,
    "tryhackme":        7, "hackthebox":      5, "ctf":             5,
    "ctf writeup":      6, "write-up":        4, "walkthrough":     6,
    "lab":              4,
    "port scanner":     7, "subdomain scanner":7,"recon tool":      7,
    "recon framework":  7, "pentest tool":    6, "pentest framework":6,
    "awesome list":     8, "cheatsheet":      6, "cheat sheet":     6,
    "wordlist":         7, "password list":   7,
    "dependabot":       9, "dependency update":9,"bump version":    9,
    "version bump":     9, "chore:":          8, "docs:":           8,
    "ci:":              8, "build:":          7, "refactor:":       7,
}

NOISE_REPOS: set[str] = {
    "projectdiscovery/httpx", "projectdiscovery/subfinder",
    "projectdiscovery/naabu", "projectdiscovery/nuclei",
    "projectdiscovery/katana", "projectdiscovery/dnsx",
    "swisskyrepo/payloadsallthethings", "danielmiessler/seclists",
    "owasp/owasp-mstg", "owasp/wstg",
}

_HIGH_CONF_KW = {
    "actively exploited", "exploited in the wild", "exploit in the wild",
    "0day", "0-day", "zero-day", "zero day", "rce", "remote code execution",
    "unauthenticated rce", "auth bypass", "authentication bypass",
    "sandbox escape", "container escape", "kernel exploit",
    "exploit released", "exploit available", "working exploit",
    "poc", "proof of concept", "proof-of-concept",
    "arbitrary code execution", "memory corruption", "use-after-free",
    "use after free", "heap overflow", "privilege escalation", "exploit chain",
}

_EXPLOIT_DEV_KW = {
    "shellcode", "rop chain", "heap grooming", "heap feng shui",
    "exploit development", "exploit writing", "exploit technique",
    "aslr bypass", "dep bypass", "cfg bypass", "bypass mitigation",
    "return oriented programming", "heap spray", "type confusion",
    "buffer overflow", "stack overflow", "out-of-bounds",
    "integer overflow", "double free", "race condition",
}

_EDUCATIONAL_KW = {
    "tutorial", "course", "beginner", "learning", "roadmap",
    "mentorship", "certification", "study guide", "getting started",
    "how to learn", "ctf", "tryhackme", "hackthebox", "walkthrough",
}

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


@dataclass
class FilterResult:
    passes:           bool
    signal_score:     int
    category:         str
    matched_signals:  list[str] = field(default_factory=list)
    negative_signals: list[str] = field(default_factory=list)


def _corpus(item: dict) -> str:
    return " ".join([
        item.get("title") or "",
        (item.get("text") or "")[:3000],
        str(item.get("metadata") or ""),
    ]).lower()


def _score_positive(corpus: str) -> tuple[int, list[str]]:
    total, matched = 0, []
    for term, pts in POSITIVE_SIGNALS.items():
        if _term_re(term).search(corpus):
            total += pts
            matched.append(term)
    cves = list(set(_CVE_RE.findall(corpus)))
    if cves:
        total += min(len(cves) * 4, 12)
        matched.extend(cves[:3])
    return total, matched


def _score_negative(title: str, corpus: str) -> tuple[int, list[str]]:
    total, matched = 0, []
    tl = title.lower()
    for term, pts in NEGATIVE_SIGNALS.items():
        pat = _term_re(term)
        if pat.search(tl):
            total += pts * 2
            matched.append(term)
        elif pat.search(corpus):
            total += pts
    if any(nr in title.lower() for nr in NOISE_REPOS):
        total += 15
    return total, matched


def _classify(pos: int, neg: int, matched: list[str]) -> str:
    ms = set(m.lower() for m in matched)
    if neg >= 10 and pos < HIGH_CONF_MIN_SCORE:
        return CAT_EDUCATIONAL if ms & _EDUCATIONAL_KW else CAT_GENERAL
    if pos >= HIGH_CONF_MIN_SCORE and ms & _HIGH_CONF_KW:
        return CAT_HIGH_CONF
    if pos >= EXPLOIT_DEV_MIN_SCORE and ms & _EXPLOIT_DEV_KW:
        return CAT_EXPLOIT_DEV
    if ms & _EDUCATIONAL_KW:
        return CAT_EDUCATIONAL
    return CAT_GENERAL


def analyze(item: dict) -> FilterResult:
    corpus = _corpus(item)
    title  = item.get("title") or ""
    pos, matched     = _score_positive(corpus)
    neg, neg_matched = _score_negative(title, corpus)
    net = max(pos - neg, 0)
    cat = _classify(pos, neg, matched)
    passes = net >= MIN_SIGNAL_SCORE and cat in (CAT_HIGH_CONF, CAT_EXPLOIT_DEV)
    return FilterResult(
        passes=passes, signal_score=net, category=cat,
        matched_signals=matched, negative_signals=neg_matched,
    )
