"""Dynamic intelligence-source manager.

A *source* is analyst-approved configuration: name, URL, type, category, trust level,
collection interval and an enabled flag. Collectors read this registry on every cycle, so
adding, editing, disabling or deleting a source takes effect without touching code.

Sources are never trusted automatically: ``trust`` is chosen deliberately and feeds the
risk score. Persisted as JSON (``data/sources.json``); written atomically under a lock.
"""
from __future__ import annotations

import ipaddress
import json
import os
import socket
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

from ingestion.jsonapi import MAPPING_KEYS, clean_mapping
from config.settings import (DATA_DIR, INTERVAL_MAX, INTERVAL_MIN, SOURCE_CATEGORIES, SOURCE_TYPES,
                             TRUST_LEVELS, TRUST_WEIGHT)
from utils.logger import get_logger
from utils.timeutil import parse_ts

logger = get_logger("source_manager")
_lock = threading.RLock()
from config.settings import USER_AGENT
MAX_BYTES = 5 * 1024 * 1024
BUILTIN_TYPES = {"builtin-nvd", "builtin-github", "builtin-reddit", "builtin-cisa-kev"}


class SourceError(ValueError):
    """Raised when a source (or its URL) is invalid or unreachable."""


# Seed feeds installed once, on first run. They are ordinary sources: editable, disable-able, deletable.
SEED_FEEDS = [
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews", "news", "medium"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/", "news", "medium"),
    ("Dark Reading", "https://www.darkreading.com/rss.xml", "news", "medium"),
    ("SecurityWeek", "https://www.securityweek.com/feed/", "news", "medium"),
    ("KrebsOnSecurity", "https://krebsonsecurity.com/feed/", "news", "medium"),
    ("Google Project Zero", "https://googleprojectzero.blogspot.com/feeds/posts/default", "research", "high"),
    ("ProjectDiscovery Blog", "https://blog.projectdiscovery.io/rss/", "research", "medium"),
    ("PortSwigger Research", "https://portswigger.net/research/rss", "research", "high"),
    ("Palo Alto Unit 42", "https://unit42.paloaltonetworks.com/feed/", "research", "high"),
    ("Microsoft Security Blog", "https://www.microsoft.com/en-us/security/blog/feed/", "vendor", "high"),
    ("Help Net Security", "https://www.helpnetsecurity.com/feed/", "news", "medium"),
    ("CyberScoop", "https://cyberscoop.com/feed/", "news", "medium"),
    ("Trend Micro Research", "https://www.trendmicro.com/en_us/research.rss", "research", "high"),
    ("Rapid7 Blog", "https://www.rapid7.com/blog/feed/", "research", "high"),
    ("CrowdStrike Blog", "https://www.crowdstrike.com/blog/feed/", "research", "high"),
    ("Recorded Future", "https://www.recordedfuture.com/feed", "research", "medium"),
    ("Zero Day Initiative", "https://www.zerodayinitiative.com/rss/published/", "research", "high"),
    ("Full Disclosure (seclists)", "https://seclists.org/rss/fulldisclosure.rss", "community", "early_signal"),
]
BUILTINS = [
    {"id": "builtin-nvd", "name": "NVD", "url": "https://services.nvd.nist.gov/rest/json/cves/2.0", "type": "api",
     "category": "official", "trust": "authoritative", "interval_minutes": 60},
    {"id": "builtin-cisa-kev", "name": "CISA KEV", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "type": "api",
     "category": "official", "trust": "authoritative", "interval_minutes": 360},
    {"id": "builtin-github", "name": "GitHub", "url": "https://api.github.com/search", "type": "api",
     "category": "research", "trust": "medium", "interval_minutes": 15},
    {"id": "builtin-reddit", "name": "Reddit", "url": "https://www.reddit.com/r/netsec", "type": "api",
     "category": "community", "trust": "early_signal", "interval_minutes": 10},
]


# ── persistence ───────────────────────────────────────────────────────────────
def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _file() -> Path:
    f = Path(os.getenv("EVVP_SOURCES_FILE") or (Path(DATA_DIR) / "sources.json"))
    f.parent.mkdir(parents=True, exist_ok=True)
    return f


def _blank(**kw) -> dict:
    base = {"enabled": True, "builtin": False, "status": "unknown", "last_fetched": None, "last_success": None,
            "last_error": None, "consecutive_failures": 0, "last_item_count": None, "total_collected": 0,
            "last_test": None, "mapping": None, "created_at": _now()}
    base.update(kw)
    return base


def _seed() -> list[dict]:
    items = [_blank(**b, builtin=True) for b in BUILTINS]
    for name, url, cat, trust in SEED_FEEDS:
        items.append(_blank(id="seed-" + uuid.uuid5(uuid.NAMESPACE_URL, url).hex[:10], name=name, url=url,
                            type="rss", category=cat, trust=trust, interval_minutes=30))
    return items


def _load() -> list[dict]:
    with _lock:
        f = _file()
        if not f.exists():
            _save(_seed())
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return [_normalise(x) for x in data if isinstance(x, dict)]
        except (OSError, json.JSONDecodeError) as exc:
            logger.error("sources file unreadable (%s); keeping a backup and re-seeding", exc)
            try:
                f.replace(f.with_suffix(".corrupt"))
            except OSError:
                pass
        items = _seed()
        _save(items)
        return items


def _normalise(x: dict) -> dict:
    """Upgrade records written by older versions (no trust/category/interval)."""
    out = _blank(**{k: v for k, v in x.items()})
    out.setdefault("id", "src-" + uuid.uuid4().hex[:12])
    out["type"] = (out.get("type") or "rss").lower()
    out["category"] = out.get("category") if out.get("category") in SOURCE_CATEGORIES else "news"
    out["trust"] = out.get("trust") if out.get("trust") in TRUST_LEVELS else "medium"
    try:
        out["interval_minutes"] = int(out.get("interval_minutes") or 30)
    except (TypeError, ValueError):
        out["interval_minutes"] = 30
    out["builtin"] = bool(out.get("builtin")) or out["id"] in BUILTIN_TYPES
    return out


def _save(items: list[dict]) -> None:
    with _lock:
        f = _file()
        tmp = f.with_suffix(".tmp")
        tmp.write_text(json.dumps(items, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, f)


# ── validation ────────────────────────────────────────────────────────────────
def _allow_private() -> bool:
    return os.getenv("EVVP_ALLOW_PRIVATE_SOURCES", "").lower() in ("1", "true", "yes")


def check_url(url: str, resolve: bool = False) -> str:
    """Validate a source URL. With ``resolve`` also refuse hosts that resolve to private/loopback
    addresses (SSRF protection: an analyst-supplied URL must not reach internal services)."""
    url = (url or "").strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise SourceError("URL must start with http:// or https:// and include a host")
    if len(url) > 2048:
        raise SourceError("URL is too long")
    if parsed.username or parsed.password:
        raise SourceError("URLs containing credentials are not allowed")
    if _allow_private():
        return url
    host = parsed.hostname.lower()
    if host in ("localhost", "metadata.google.internal") or host.endswith((".local", ".internal")):
        raise SourceError("Internal hostnames are not allowed as sources")
    if resolve:
        try:
            infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80))
        except socket.gaierror:
            raise SourceError(f"Host {host} cannot be resolved")
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                raise SourceError("Host resolves to a private or reserved address; refusing to fetch")
    else:
        try:
            ip = ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            ip = None                                   # a hostname, not an IP literal
        if ip is not None and (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            raise SourceError("Private IP addresses are not allowed as sources")
    return url


def _clean(data: dict, partial: bool, current: dict | None = None) -> dict:
    out: dict = {}
    if not isinstance(data, dict):
        raise SourceError("Request body must be a JSON object")
    if "name" in data or not partial:
        name = data.get("name")
        if not isinstance(name, str) or not name.strip():
            raise SourceError("Source name is required")
        if len(name.strip()) > 120:
            raise SourceError("Source name is too long (max 120)")
        out["name"] = name.strip()
    if "url" in data or not partial:
        if current and current.get("builtin"):
            if "url" in data and str(data["url"]).strip() != current["url"]:
                raise SourceError("The URL of a built-in source cannot be changed")
        else:
            out["url"] = check_url(data.get("url"))
    if "type" in data or not partial:
        t = str(data.get("type") or "rss").lower().strip()
        if t not in SOURCE_TYPES:
            raise SourceError(f"type must be one of: {', '.join(SOURCE_TYPES)}")
        out["type"] = t
    if "category" in data or not partial:
        c = str(data.get("category") or "news").lower().strip()
        if c not in SOURCE_CATEGORIES:
            raise SourceError(f"category must be one of: {', '.join(SOURCE_CATEGORIES)}")
        out["category"] = c
    if "trust" in data or not partial:
        t = str(data.get("trust") or "medium").lower().strip()
        if t not in TRUST_LEVELS:
            raise SourceError(f"trust must be one of: {', '.join(TRUST_LEVELS)}")
        out["trust"] = t
    if "interval_minutes" in data or not partial:
        v = data.get("interval_minutes", 30)
        if isinstance(v, bool) or not isinstance(v, (int, float)) or int(v) != v:
            raise SourceError("interval_minutes must be a whole number")
        if not INTERVAL_MIN <= int(v) <= INTERVAL_MAX:
            raise SourceError(f"interval_minutes must be between {INTERVAL_MIN} and {INTERVAL_MAX}")
        out["interval_minutes"] = int(v)
    eff_type = out.get("type") or (current or {}).get("type") or "rss"
    if eff_type in ("api", "custom") and not (current or {}).get("builtin"):
        if "mapping" in data or not partial or ((current or {}).get("mapping") is None and "type" in data):
            try:
                out["mapping"] = clean_mapping(data.get("mapping") if "mapping" in data else (current or {}).get("mapping"))
            except ValueError as exc:
                raise SourceError(f"{exc} (API/custom sources are collected through a JSON field mapping)")
    elif eff_type in ("rss", "atom") and ("mapping" in data or "type" in data):
        out["mapping"] = None                                   # a mapping only makes sense for API/custom sources
    if "enabled" in data:
        if not isinstance(data["enabled"], bool):
            raise SourceError("enabled must be true or false")
        out["enabled"] = data["enabled"]
    return out


def _key(url: str) -> str:
    p = urlparse(url.strip().lower())
    return f"{p.netloc.replace('www.', '')}{p.path.rstrip('/')}?{p.query}"


# ── CRUD ──────────────────────────────────────────────────────────────────────
def options() -> dict:
    return {"mapping_fields": list(MAPPING_KEYS), "types": list(SOURCE_TYPES), "categories": list(SOURCE_CATEGORIES), "trust": list(TRUST_LEVELS),
            "trust_weight": TRUST_WEIGHT, "interval_minutes": {"min": INTERVAL_MIN, "max": INTERVAL_MAX}}


def collectable(src: dict) -> bool:
    """Whether EVVP has a collector for this source (RSS/Atom generically; built-ins by their own collector)."""
    return src["type"] in ("rss", "atom") or src["id"] in BUILTIN_TYPES or bool(src.get("mapping"))


def generic(src: dict) -> bool:
    """True for sources collected by the generic collector (RSS/Atom, or API/custom with a field mapping); False for built-ins."""
    return not src.get("builtin") and (src["type"] in ("rss", "atom") or (src["type"] in ("api", "custom") and bool(src.get("mapping"))))


def list_sources() -> list[dict]:
    return [{**s, "collectable": collectable(s)} for s in _load()]


def get_source(source_id: str) -> dict | None:
    return next((s for s in list_sources() if s["id"] == source_id), None)


def add_source(data: dict) -> dict:
    fields = _clean(data, partial=False)
    with _lock:
        items = _load()
        if any(_key(x["url"]) == _key(fields["url"]) for x in items):
            raise SourceError("A source with this URL already exists")
        item = _blank(id="src-" + uuid.uuid4().hex[:12], **fields)
        if "enabled" in fields:
            item["enabled"] = fields["enabled"]
        items.append(item)
        _save(items)
    return {**item, "collectable": collectable(item)}


def update_source(source_id: str, changes: dict) -> dict:
    with _lock:
        items = _load()
        target = next((x for x in items if x["id"] == source_id), None)
        if target is None:
            raise KeyError("Source not found")
        fields = _clean(changes, partial=True, current=target)
        if "url" in fields and any(x["id"] != source_id and _key(x["url"]) == _key(fields["url"]) for x in items):
            raise SourceError("A source with this URL already exists")
        if "url" in fields and fields["url"] != target["url"]:   # a new URL invalidates the old health data
            target.update(status="unknown", last_error=None, consecutive_failures=0, last_fetched=None)
        target.update(fields)
        _save(items)
        return {**target, "collectable": collectable(target)}


def delete_source(source_id: str) -> bool:
    with _lock:
        items = _load()
        target = next((x for x in items if x["id"] == source_id), None)
        if target is None:
            raise KeyError("Source not found")
        if target.get("builtin"):
            raise SourceError("Built-in sources cannot be deleted; disable them instead")
        _save([x for x in items if x["id"] != source_id])
    return True


# ── scheduling / health ───────────────────────────────────────────────────────
def enabled_feeds() -> list[dict]:
    return [s for s in list_sources() if s["enabled"] and generic(s)]


def due(source: dict, now: datetime | None = None) -> bool:
    """True when the source is enabled and its interval (plus failure back-off) has elapsed."""
    if not source.get("enabled", True):
        return False
    last = parse_ts(source.get("last_fetched"))
    if last is None:
        return True
    interval = timedelta(minutes=int(source.get("interval_minutes") or 30))
    fails = int(source.get("consecutive_failures") or 0)
    if fails:                                         # exponential back-off, capped at 6 hours
        interval = min(interval * (2 ** min(fails, 5)), timedelta(hours=6))
    return (now or datetime.now(timezone.utc)) >= last + interval


def gate(source_id: str, force: bool = False) -> dict | None:
    """Return the source if its collector should run now (enabled, and due unless ``force``), else None."""
    src = get_source(source_id)
    return src if src and src["enabled"] and (force or due(src)) else None


def mark_fetch(source_id: str, success: bool = True, error: str | None = None,
               item_count: int | None = None, new_items: int = 0) -> dict | None:
    with _lock:
        items = _load()
        t = next((x for x in items if x["id"] == source_id), None)
        if t is None:
            return None
        t["last_fetched"] = _now()
        if success:
            t.update(status="healthy", last_success=t["last_fetched"], last_error=None, consecutive_failures=0)
            if item_count is not None:
                t["last_item_count"] = item_count
            t["total_collected"] = int(t.get("total_collected") or 0) + int(new_items)
        else:
            t.update(status="error", last_error=str(error or "Unknown error")[:300],
                     consecutive_failures=int(t.get("consecutive_failures") or 0) + 1)
        _save(items)
        return dict(t)


def record_test(source_id: str, ok: bool, error: str | None = None) -> None:
    with _lock:
        items = _load()
        t = next((x for x in items if x["id"] == source_id), None)
        if t:
            t["last_test"] = {"ts": _now(), "ok": ok, "error": error}
            _save(items)


# ── fetching / testing ────────────────────────────────────────────────────────
def safe_get(url: str, timeout: int = 20, max_redirects: int = 3):
    """GET with SSRF checks on every redirect hop and a response-size cap. Raises SourceError/requests errors."""
    for _ in range(max_redirects + 1):
        check_url(url, resolve=True)
        r = requests.get(url, headers={"User-Agent": USER_AGENT, "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*"},
                         timeout=timeout, allow_redirects=False)
        if getattr(r, "is_redirect", False) or getattr(r, "status_code", 200) in (301, 302, 303, 307, 308):
            loc = (r.headers or {}).get("Location")
            if not loc:
                raise SourceError("Redirect without a Location header")
            url = urljoin(url, loc)
            continue
        r.raise_for_status()
        clen = (r.headers or {}).get("Content-Length")
        if (clen and clen.isdigit() and int(clen) > MAX_BYTES) or len(r.content) > MAX_BYTES:
            raise SourceError("Response is larger than 5 MB; refusing to parse")
        return r
    raise SourceError("Too many redirects")


def test_source(url: str, source_type: str = "rss", limit: int = 5, mapping: dict | None = None) -> dict:
    """Fetch and parse a source. Raises SourceError with a human-readable reason on any failure."""
    from ingestion.feedparse import FeedError, parse_feed   # local import: avoids a package cycle
    from ingestion.jsonapi import parse_json_feed
    source_type = (source_type or "rss").lower()
    try:
        r = safe_get(check_url(url))
    except SourceError:
        raise
    except requests.Timeout:
        raise SourceError("The source timed out (no response within 20 seconds)")
    except requests.HTTPError as exc:
        raise SourceError(f"The source returned an error: {exc}")
    except requests.RequestException as exc:
        raise SourceError(f"Could not connect to the source: {exc}")
    if source_type in ("api", "custom") and mapping:
        try:
            feed = parse_json_feed(r.content, mapping)
        except (FeedError, ValueError) as exc:
            raise SourceError(str(exc))
        entries = feed["entries"]
        return {"valid": True, "feed_title": "JSON API", "entry_count": len(entries), "status_code": r.status_code,
                "entries": [{"title": e["title"], "url": e["link"], "published": e["published"]} for e in entries[:limit]]}
    if source_type not in ("rss", "atom"):
        return {"valid": True, "status_code": r.status_code, "entry_count": None, "entries": [],
                "note": "Reachable. Add a field mapping (items_path, title_field, …) to collect this API/custom source."}
    try:
        feed = parse_feed(r.content)
    except FeedError as exc:
        raise SourceError(str(exc))
    entries = feed["entries"]
    return {"valid": True, "feed_title": feed["feed_title"], "entry_count": len(entries), "status_code": r.status_code,
            "entries": [{"title": e["title"], "url": e["link"], "published": e["published"]} for e in entries[:limit]]}
