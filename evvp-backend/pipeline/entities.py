"""Vulnerability entity engine.

Collected items (blog posts, GitHub repos, NVD records, ...) are *evidence*.
This module groups the evidence that describes the same vulnerability into one
**entity**, so the same flaw reported by a blog, a PoC repo and NVD is one
finding with a cross-source count, a timeline and a measurable lead time --
not three unrelated alerts.

Grouping rules
  * Evidence that carries a CVE id belongs to that CVE's entity. An article that
    names up to BRIDGE_MAX CVEs bridges them into one entity; a roundup that
    names more is attached to each CVE but never bridges them.
  * Evidence without a CVE is clustered by distinctive-title similarity and, when
    it matches an item already in a CVE entity, joins that entity. This is how an
    early, CVE-less signal is later linked to its CVE.

Timestamps are never invented: an evidence record without a parseable time is
counted as a mention but excluded from timing.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from pipeline.risk import (
    active_exploitation, attack_techniques, build_intelligence, cvss_of, has_term,
    poc_available, severity_from_cvss, severity_from_risk, ZERO,
)
from utils.timeutil import format_duration, iso, parse_ts

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
BRIDGE_MAX = 3
SIM_THRESHOLD = 0.5
SIM_MIN_SHARED = 3
_STOP = {
    "vulnerability", "vulnerabilities", "exploit", "exploited", "exploits", "security", "remote", "code",
    "execution", "critical", "flaw", "flaws", "patch", "patches", "patched", "released", "release", "attack",
    "attacks", "attackers", "hackers", "actively", "researchers", "researcher", "update", "updates", "with",
    "from", "that", "this", "into", "after", "over", "using", "used", "have", "been", "their", "which",
    "could", "allow", "allows", "affecting", "impacting", "against", "about", "than", "more", "newly",
    "zero", "days", "dubbed", "show", "shows", "showing", "gets", "unpatched", "bug", "bugs", "issue",
    "wild", "exploitation", "exploiting", "public", "publicly", "available", "disclosed", "discloses", "disclosure", "vendor",
    "confirms", "confirmed", "reported", "reports", "reportedly", "software", "firmware", "version", "versions", "users",
    "servers", "devices", "appliances", "products", "product", "systems", "platform", "instances", "customers", "latest",
    "urgent", "advisory", "alert", "fixes", "fixed", "fixing", "arbitrary", "executes", "execute", "hits", "hit", "hijack",
    "takeover", "chain", "multiple", "several", "major", "serious", "severe", "high", "severity", "risk", "threat", "threats",
}
from config.settings import DATA_DIR as _DATA_DIR


VULN_TYPES = {
    "Remote Code Execution": ("remote code execution", "rce", "arbitrary code execution", "code execution"),
    "Privilege Escalation": ("privilege escalation", "lpe", "eop", "sandbox escape", "container escape"),
    "Authentication Bypass": ("authentication bypass", "auth bypass", "authorization bypass", "broken access control", "unauthenticated"),
    "Injection": ("sql injection", "command injection", "xxe", "xml external entity", "deserialization"),
    "Memory Corruption": ("buffer overflow", "heap overflow", "stack overflow", "use-after-free", "use after free",
                          "memory corruption", "out-of-bounds", "type confusion", "double free", "integer overflow"),
    "SSRF / Path Traversal": ("ssrf", "server-side request forgery", "path traversal"),
    "Supply Chain": ("supply chain", "malicious package", "typosquatting", "dependency confusion", "backdoor"),
}


def vuln_types(text: str) -> list[str]:
    text = text.lower()
    return [name for name, terms in VULN_TYPES.items()
            if has_term(text, terms) is not None]


# ── helpers ───────────────────────────────────────────────────────────────────
def _tokens(title: str) -> set[str]:
    return {t for t in re.findall(r"[a-z0-9]{4,}", (title or "").lower()) if t not in _STOP}


def _sim(a: set[str], b: set[str]) -> tuple[float, int]:
    if not a or not b:
        return 0.0, 0
    inter = len(a & b)
    return inter / len(a | b), inter


def _item_cves(item: dict) -> list[str]:
    found = {c.upper() for c in (item.get("cve_ids") or [])}
    found |= {c.upper() for c in _CVE_RE.findall(f"{item.get('title','')} {(item.get('text') or '')[:1500]}")}
    return sorted(found)


def _domain(url: str) -> str:
    return (urlparse(url or "").netloc or "unknown").lower().replace("www.", "")


_SECOND_LEVEL = {"co", "com", "org", "net", "ac", "gov", "edu", "blogspot", "wordpress", "medium", "substack"}


def source_key(label: str) -> str:
    """Canonical publisher identity so "The Hacker News" and "thehackernews.com" are one source."""
    s = re.sub(r"^https?://", "", (label or "").strip().lower()).split("/")[0].replace("www.", "")
    if "." in s and " " not in s:                       # domain-like -> registrable label
        parts = [p for p in s.split(".") if p]
        if len(parts) > 1:
            parts.pop()                                 # always drop the TLD (any TLD, known or not)
        while len(parts) > 1 and parts[-1] in _SECOND_LEVEL:
            parts.pop()                                 # co.uk, blogspot.com, ...
        s = parts[-1] if parts else s
    return re.sub(r"[^a-z0-9]", "", s)


def _canonical_sources(evidence: list[dict]) -> list[str]:
    """Rewrite each row's ``source`` to one display name per publisher; return the distinct names.

    Preference: a human-readable name (from the Source Manager) over a bare domain.
    """
    chosen: dict[str, str] = {}
    for e in evidence:
        k = source_key(e["source"])
        cur = chosen.get(k)
        domain_like = "." in e["source"] and " " not in e["source"]
        if cur is None or ((("." in cur and " " not in cur)) and not domain_like):
            chosen[k] = e["source"]
    for e in evidence:
        e["source"] = chosen[source_key(e["source"])]
    return sorted(set(chosen.values()))


def source_label(item: dict) -> str:
    p = item.get("platform")
    md = item.get("metadata") or {}
    if p == "nvd":
        return "NVD"
    if p == "github":
        return "GitHub"
    if p == "reddit":
        return "Reddit"
    if p == "cisa":
        return "CISA KEV"
    return md.get("source_name") or md.get("feed_title") or _domain(item.get("source") or item.get("url") or "")


def _evidence_type(item: dict) -> str:
    p = item.get("platform")
    if p == "nvd":
        return "nvd_record"
    if p == "cisa":
        return "kev_listing"
    md = item.get("metadata") or {}
    if p == "github":
        return "poc_detected" if poc_available(item) else "github_activity"
    if p == "reddit":
        return "community_signal"
    if md.get("source_category") in ("vendor", "official"):
        return "vendor_advisory"
    return "researcher_report" if md.get("source_category") == "research" else "news_report"


_TYPE_LABEL = {
    "nvd_record": "NVD record published", "poc_detected": "PoC / exploit code detected",
    "github_activity": "GitHub activity", "community_signal": "Community discussion",
    "vendor_advisory": "Vendor / official advisory", "researcher_report": "Researcher report",
    "news_report": "Security news report", "cve_published": "CVE published",
    "roundup_mention": "Mentioned in a CVE roundup", "kev_listing": "Added to CISA KEV (confirmed exploited)",
}


def _evidence_for(item: dict) -> list[dict]:
    """One primary evidence row plus one row per extra source URL attached by dedup."""
    cves = _item_cves(item)
    observed = parse_ts(item.get("timestamp"))
    collected = parse_ts(item.get("collected_at"))
    primary_url = item.get("url") or ""
    rows = [{
        "item_id": item.get("id"), "platform": item.get("platform"), "source": source_label(item),
        "url": primary_url, "title": item.get("title") or "", "type": _evidence_type(item),
        "trust": item.get("source_trust") or "medium",
        "observed_at": observed, "collected_at": collected, "cves": cves, "primary": True,
    }]
    seen = {primary_url}
    for extra in item.get("sources") or []:
        url = (extra or {}).get("url") or ""
        if not url or url in seen:
            continue
        seen.add(url)
        rows.append({
            "item_id": item.get("id"), "platform": extra.get("platform") or item.get("platform"),
            "source": extra.get("source") or _domain(url), "url": url,
            "title": extra.get("title") or item.get("title") or "",
            "type": extra.get("evidence_type") or "news_report", "trust": extra.get("trust") or "medium",
            "observed_at": parse_ts(extra.get("observed_at")), "collected_at": parse_ts(extra.get("collected_at")),
            "cves": cves, "primary": False,
        })
    return rows


class _DSU:
    def __init__(self):
        self.p: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[rb] = ra


# ── timing ────────────────────────────────────────────────────────────────────
def compute_timing(evidence: list[dict], cve_published: datetime | None) -> dict:
    """First-seen and early-detection lead time. Only uses real timestamps."""
    observed = [e["observed_at"] for e in evidence if e["observed_at"]]
    collected = [e["collected_at"] for e in evidence if e["collected_at"]]
    early_obs = [e["observed_at"] for e in evidence
                 if e["observed_at"] and e["platform"] != "nvd" and not e.get("context")]
    first_seen = min(observed + collected) if (observed or collected) else None
    first_public = min(observed) if observed else None
    first_collected = min(collected) if collected else None

    lead = {"seconds": None, "human": None, "basis": None, "status": "no_timestamp", "note": ""}
    if cve_published is None:
        lead.update(status="no_cve", note="No CVE publication timestamp available yet")
    else:
        det = (cve_published - first_collected).total_seconds() if first_collected else None
        pub = (cve_published - min(early_obs)).total_seconds() if early_obs else None
        if det is not None and det > 0:
            lead.update(seconds=det, basis="evvp_detection", status="early",
                        note="EVVP collected this before the CVE was published")
        elif pub is not None and pub > 0:
            lead.update(seconds=pub, basis="public_signal", status="early",
                        note="A public signal pre-dates the CVE; EVVP collected it after publication")
        elif pub is not None:
            lead.update(seconds=pub, basis="public_signal", status="after_cve",
                        note="Earliest non-NVD signal appeared after the CVE was published")
        else:
            lead.update(status="no_signal", note="No non-NVD evidence with a reliable timestamp")
        if lead["seconds"] is not None:
            lead["human"] = format_duration(abs(lead["seconds"]))
    return {
        "first_seen": iso(first_seen), "first_public_signal": iso(first_public),
        "first_collected": iso(first_collected), "cve_published": iso(cve_published), "lead_time": lead,
    }


def _timeline(evidence: list[dict], cve_published: datetime | None, first_seen_iso: str | None) -> dict:
    events, undated = [], 0
    have_nvd_row = any(e["type"] == "nvd_record" and e["observed_at"] for e in evidence)
    for e in evidence:
        ts = e["observed_at"] or e["collected_at"]
        if ts is None:
            undated += 1
            continue
        events.append({"ts": iso(ts), "type": e["type"], "label": _TYPE_LABEL.get(e["type"], e["type"]),
                       "source": e["source"], "url": e["url"], "title": e["title"],
                       "basis": "published" if e["observed_at"] else "collected"})
    if cve_published and not have_nvd_row:
        events.append({"ts": iso(cve_published), "type": "cve_published", "label": _TYPE_LABEL["cve_published"],
                       "source": "NVD", "url": "", "title": "", "basis": "published"})
    events.sort(key=lambda x: x["ts"])
    if events and first_seen_iso:
        events[0]["first_observed"] = True
    return {"events": events, "undated_mentions": undated}


# ── entity building ───────────────────────────────────────────────────────────
def _merge_nvd(items: list[dict]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for it in items:
        for rec in it.get("nvd_data") or []:
            cid = (rec.get("cve_id") or "").upper()
            if cid and (cid not in out or (rec.get("modified") or "") > (out[cid].get("modified") or "")):
                out[cid] = rec
    return out


def _merge_epss(items: list[dict]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for it in items:
        for rec in it.get("epss_data") or []:
            out[(rec.get("cve_id") or "").upper()] = rec
    return out


def _strip(text: str, n: int = 600) -> str:
    text = re.sub(r"<[^>]+>", " ", text or "")
    return re.sub(r"\s+", " ", text).strip()[:n]


def build_entities(items: list[dict], verifications: list[dict] | None = None,
                   decisions: dict[str, dict] | None = None, now: datetime | None = None) -> list[dict]:
    now = now or datetime.now(timezone.utc)
    ver_by_raw = {v.get("raw_id"): v for v in (verifications or [])}
    dsu = _DSU()
    by_id = {i["id"]: i for i in items if i.get("id")}

    noncve_ids: list[str] = []
    item_cves: dict[str, list[str]] = {}
    roundups: set[str] = set()      # items naming > BRIDGE_MAX CVEs (e.g. "July CVE landscape")
    for iid, it in by_id.items():
        cves = _item_cves(it)
        item_cves[iid] = cves
        if not cves:
            noncve_ids.append(iid)
            dsu.find(f"i:{iid}")
            continue
        if len(cves) > BRIDGE_MAX:
            roundups.add(iid)       # its own entity; attached to CVE entities only as context
            dsu.find(f"i:{iid}")
            continue
        for c in cves:
            dsu.find(f"c:{c}")
        for c in cves[1:]:
            dsu.union(f"c:{cves[0]}", f"c:{c}")

    # Non-CVE evidence: cluster by title; join CVE entities on strong similarity.
    toks = {iid: _tokens(by_id[iid].get("title")) for iid in by_id}
    cve_member_ids = [iid for iid, cv in item_cves.items()
                      if cv and iid not in roundups and by_id[iid].get("platform") != "nvd"]
    order = sorted(noncve_ids, key=lambda i: str(by_id[i].get("collected_at") or ""))
    assigned: list[str] = []
    for iid in order:
        best, best_node = 0.0, None
        for other in cve_member_ids + assigned:
            s, shared = _sim(toks[iid], toks[other])
            if s >= SIM_THRESHOLD and shared >= SIM_MIN_SHARED and s > best:
                best, best_node = s, (f"c:{item_cves[other][0]}" if item_cves[other] else f"i:{other}")
        if best_node:
            dsu.union(best_node, f"i:{iid}")
        assigned.append(iid)

    # Group core items by DSU root; roundups are context for every CVE entity they name.
    groups: dict[str, set[str]] = defaultdict(set)
    context: dict[str, set[str]] = defaultdict(set)
    for iid, cves in item_cves.items():
        if not cves or iid in roundups:
            groups[dsu.find(f"i:{iid}")].add(iid)
        else:
            groups[dsu.find(f"c:{cves[0]}")].add(iid)
    for iid in roundups:
        for c in item_cves[iid]:
            if f"c:{c}" in dsu.p:
                context[dsu.find(f"c:{c}")].add(iid)

    entities = []
    for root, ids in groups.items():
        members = [by_id[i] for i in ids]
        ctx = [by_id[i] for i in context.get(root, set()) if i not in ids]
        entities.append(_make_entity(members, item_cves, ver_by_raw, decisions or {}, now,
                                     context=ctx, roundup=bool(ids & roundups)))
    entities.sort(key=lambda e: (e["risk_score"], e["last_updated"] or ""), reverse=True)
    return entities


def _make_entity(members: list[dict], item_cves: dict, ver_by_raw: dict, decisions: dict, now: datetime,
                 context: list[dict] | None = None, roundup: bool = False) -> dict:
    members.sort(key=lambda m: (str(m.get("collected_at") or ""), m.get("id") or ""))
    anchor = members[0]["id"]
    ent_id = "ent-" + hashlib.sha1(anchor.encode()).hexdigest()[:12]

    cves = sorted({c for m in members for c in item_cves.get(m["id"], [])})
    evidence = [row for m in members for row in _evidence_for(m)]
    for cm in context or []:        # roundup articles: counted as mentions, never drive scoring/title
        for row in _evidence_for(cm):
            row["cves"] = [c for c in row["cves"] if c in cves]
            row["type"] = "roundup_mention"
            row["context"] = True
            evidence.append(row)
    nvd = _merge_nvd(members)
    epss = _merge_epss(members)
    if roundup:        # an article about many CVEs is not itself one vulnerability: no borrowed CVSS/EPSS/dates
        nvd, epss = {}, {}
    cve_pub = min((p for p in (parse_ts(r.get("published")) for r in nvd.values()) if p), default=None)
    nvd_item_pub = min((e["observed_at"] for e in evidence if e["platform"] == "nvd" and e["observed_at"]), default=None)
    cve_pub = min([p for p in (cve_pub, nvd_item_pub) if p], default=None)

    sources = _canonical_sources(evidence)
    # Merged view used by the shared scoring functions
    trust_w = max((m.get("source_trust_weight") or 0) for m in members)
    best_trust = next((m.get("source_trust") for m in members if (m.get("source_trust_weight") or 0) == trust_w), None)
    non_nvd = [m for m in members if m.get("platform") != "nvd"] or members
    lead_item = max(non_nvd, key=lambda m: m.get("signal_score") or 0)
    verified_poc = any((ver_by_raw.get(m["id"]) or {}).get("poc_found") for m in members)
    merged = {
        "title": lead_item.get("title") or "", "platform": lead_item.get("platform"),
        "text": " ".join((m.get("text") or "")[:1500] for m in members),
        "summary": lead_item.get("summary") or "",
        "signal_score": max((m.get("signal_score") or 0) for m in members),
        "cve_ids": cves, "nvd_data": list(nvd.values()),
        "epss": max((r["epss"] for r in epss.values()), default=None),
        "source_trust": best_trust, "source_trust_weight": trust_w or None,
        "verification": {"poc_found": verified_poc},
        "kev": any(m.get("kev") for m in members),
    }
    csc = len(sources)
    intel = build_intelligence(merged, csc)
    cvss = cvss_of(merged)
    severity = severity_from_cvss(cvss) if cvss else severity_from_risk(intel["risk_score"])

    timing = compute_timing(evidence, cve_pub)
    timeline = _timeline(evidence, cve_pub, timing["first_seen"])
    stamps = [e["observed_at"] or e["collected_at"] for e in evidence if (e["observed_at"] or e["collected_at"])]
    last_updated = max(stamps) if stamps else None
    # NVD last-modified counts as an update
    mods = [m for m in (parse_ts(r.get("modified")) for r in nvd.values()) if m]
    if mods and (last_updated is None or max(mods) > last_updated):
        last_updated = max(mods)

    # trend / velocity
    def at(e):
        return e["observed_at"] or e["collected_at"]
    r24 = sum(1 for e in evidence if at(e) and now - timedelta(hours=24) <= at(e) <= now)
    p24 = sum(1 for e in evidence if at(e) and now - timedelta(hours=48) <= at(e) < now - timedelta(hours=24))
    mentions = len(evidence)
    active = active_exploitation(merged)
    poc = poc_available(merged) or verified_poc or any(e["type"] == "poc_detected" for e in evidence)
    zd_candidate = intel["zero_day_candidate"]
    trend_score = round(mentions * 3 + csc * 5 + r24 * 4 + intel["risk_score"] * 0.3
                        + (10 if active else 0) + (6 if zd_candidate else 0), 1)

    products = []
    for m in members:
        for p in (ver_by_raw.get(m["id"]) or {}).get("affected_products") or []:
            if p not in products and not re.match(r"(?i)^cve-\d{4}-\d+$", str(p).strip()):   # a CVE id is not a product
                products.append(p)
    for r in nvd.values():
        for p in r.get("affected_products") or []:
            if p not in products:
                products.append(p)

    desc_src = next(iter(nvd.values()), None)
    description = (desc_src or {}).get("description") or _strip(lead_item.get("summary") or lead_item.get("text"))
    title = lead_item.get("title") or ""
    if lead_item.get("platform") == "nvd" and description:
        title = f"{title} — {description[:90]}"

    # analyst decision (latest wins); match by entity id or any shared item id
    item_ids = sorted({m["id"] for m in members})
    decision = None
    for d in decisions.values():
        if d.get("entity_id") == ent_id or set(d.get("item_ids") or []) & set(item_ids):
            if decision is None or (d.get("ts") or "") > (decision.get("ts") or ""):
                decision = d

    return {
        "id": ent_id, "title": title, "description": description,
        "cve_ids": cves, "primary_cve": cves[0] if cves else None,
        "has_cve": bool(cves),
        "platforms": sorted({e["platform"] for e in evidence if e["platform"]}),
        "sources": sources, "cross_source_count": csc, "mentions": mentions,
        "evidence": [{**e, "observed_at": iso(e["observed_at"]), "collected_at": iso(e["collected_at"])} for e in evidence],
        "item_ids": item_ids,
        "risk_score": intel["risk_score"], "risk_breakdown": intel["risk_breakdown"],
        "risk_reasons": intel["risk_reasons"], "severity": severity, "roundup": roundup,
        "cvss": cvss or None,
        "cvss_vector": next((r["cvss_v3"].get("vector") for r in nvd.values() if (r.get("cvss_v3") or {}).get("vector")), None),
        "epss": merged["epss"],
        "epss_percentile": max((r["percentile"] for r in epss.values()), default=None),
        "epss_date": max((r.get("date") or "" for r in epss.values()), default="") or None,
        "zero_day_candidate": zd_candidate, "zero_day_score": intel["zero_day_score"],
        "zero_day_evidence": intel["zero_day_evidence"],
        "poc": bool(poc), "active_exploitation": bool(active), "kev": bool(merged["kev"]),
        "vendor_confirmed": any(e["type"] == "vendor_advisory" for e in evidence),
        "nvd_confirmed": bool(nvd) or any(e["platform"] == "nvd" for e in evidence),
        "nvd_status": next((m.get("nvd_status") for m in members if m.get("nvd_status") in ("unavailable", "partial", "not_found") and not nvd), None),
        "attack_techniques": intel["attack_techniques"],
        "vuln_types": vuln_types(f"{merged['title']} {merged['text'][:3000]}"),
        "categories": sorted({m.get("category") for m in members if m.get("category")}),
        "matched_signals": sorted({s for m in members for s in (m.get("matched_signals") or []) if not _CVE_RE.fullmatch(s)})[:12],
        "affected_products": products[:12],
        "references": sorted({u for r in nvd.values() for u in (r.get("references") or [])})[:15],
        "signal_score": merged["signal_score"],
        "source_trust": best_trust,
        **timing, "timeline": timeline,
        "last_updated": iso(last_updated),
        "analyst": {"status": (decision or {}).get("status", "potential"), "decision": decision},
        "trend": {"score": trend_score, "recent_24h": r24, "previous_24h": p24,
                  "velocity": r24 - p24, "direction": "up" if r24 > p24 else "down" if r24 < p24 else "flat"},
    }


# ── CVE-centric view ──────────────────────────────────────────────────────────
def build_cve_records(entities: list[dict], items: list[dict]) -> list[dict]:
    """One record per CVE id, enriched from NVD/EPSS and linked to its entity."""
    nvd = _merge_nvd(items)
    epss = _merge_epss(items)
    out = []
    owned = {c for e in entities if not e["roundup"] for c in e["cve_ids"]}
    emitted: set[str] = set()
    for ent in entities:                       # entities arrive sorted by risk, so the best owner wins
        for cid in ent["cve_ids"]:
            if (ent["roundup"] and cid in owned) or cid in emitted:
                continue
            emitted.add(cid)
            ev = [e for e in ent["evidence"] if cid in (e.get("cves") or [])]
            rec = nvd.get(cid)
            ep = epss.get(cid)
            ev_rows = [{**e, "observed_at": parse_ts(e["observed_at"]), "collected_at": parse_ts(e["collected_at"])} for e in ev]
            pub = parse_ts((rec or {}).get("published"))
            if pub is None:
                pub = min((e["observed_at"] for e in ev_rows if e["platform"] == "nvd" and e["observed_at"]), default=None)
            timing = compute_timing(ev_rows, pub)
            cvss3 = (rec or {}).get("cvss_v3") or {}
            out.append({
                "cve_id": cid, "entity_id": ent["id"],
                "description": (rec or {}).get("description") or "",
                "cvss": cvss3.get("score"), "cvss_vector": cvss3.get("vector"),
                "severity": (cvss3.get("severity") or "").upper() or ent["severity"],
                "cvss_source": "nvd" if cvss3 else None,
                "epss": ep["epss"] if ep else None, "epss_percentile": ep["percentile"] if ep else None,
                "published": (rec or {}).get("published") or iso(pub),
                "modified": (rec or {}).get("modified"),
                "references": (rec or {}).get("references") or [],
                "affected_products": (rec or {}).get("affected_products") or ent["affected_products"],
                "nvd_available": rec is not None,
                "sources": sorted({e["source"] for e in ev}), "cross_source_count": len({e["source"] for e in ev}) or 0,
                "mentions": len(ev),
                "risk_score": ent["risk_score"], "risk_breakdown": ent["risk_breakdown"],
                "poc": ent["poc"], "active_exploitation": ent["active_exploitation"],
                "attack_techniques": ent["attack_techniques"],
                "title": ent["title"], "analyst": ent["analyst"],
                **timing,
                "timeline": _timeline(ev_rows, pub, timing["first_seen"]),
                "last_updated": ent["last_updated"],
                "trend": ent["trend"],
            })
    out.sort(key=lambda r: (r["risk_score"], r["last_updated"] or ""), reverse=True)
    return out


def save_snapshot(entities: list[dict]) -> None:
    """Persist the entity table (storage requirement: vulnerability entities)."""
    try:
        os.makedirs(_DATA_DIR, exist_ok=True)
        slim = [{k: v for k, v in e.items() if k not in ("evidence", "timeline")} for e in entities]
        tmp = os.path.join(_DATA_DIR, "entities.json.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"generated_at": datetime.now(timezone.utc).isoformat(), "count": len(slim), "entities": slim}, f)
        os.replace(tmp, os.path.join(_DATA_DIR, "entities.json"))
    except OSError:
        pass
