import time
from datetime import datetime, timezone

import requests

from config.settings import (
    GITHUB_TOKEN, GITHUB_KEYWORDS, GITHUB_VULN_ORGS,
    GITHUB_REQUESTS_PER_HOUR, GITHUB_POLL_INTERVAL,
)
from database.storage import save
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter
from utils.retry import retry
from utils.signal_filter import analyze

logger = get_logger("github_collector")

_limiter = RateLimiter(GITHUB_REQUESTS_PER_HOUR)
_BASE = "https://api.github.com"
_HEADERS = {
    "Accept": "application/vnd.github+json",
    **({"Authorization": f"Bearer {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}),
}


@retry(max_attempts=3, base_delay=15.0, exceptions=(requests.RequestException,))
def _get(url: str, params: dict = None) -> dict | list:
    _limiter.wait()
    r = requests.get(url, headers=_HEADERS, params=params, timeout=20)
    if r.status_code == 403:
        reset = int(r.headers.get("X-RateLimit-Reset", time.time() + 60))
        wait = max(reset - time.time(), 5)
        logger.warning("GitHub rate limit hit — sleeping %.0fs", wait)
        time.sleep(wait)
        r = requests.get(url, headers=_HEADERS, params=params, timeout=20)
    r.raise_for_status()
    return r.json()


def _ts(val: str | None) -> str:
    return val or datetime.now(timezone.utc).isoformat()


def _save_if_signal(item: dict) -> bool:
    r = analyze(item)
    if not r.passes:
        return False
    item["signal_score"]     = r.signal_score
    item["category"]         = r.category
    item["matched_signals"]  = r.matched_signals
    item["negative_signals"] = r.negative_signals
    save(item)
    return True


# ── Keyword: repositories — sorted by CREATED to surface new exploit repos ───

def _search_repos(keyword: str) -> tuple[int, int]:
    data = _get(f"{_BASE}/search/repositories", {
        "q": f"{keyword} created:>2020-01-01",
        "sort": "updated",   # updated keeps it fresh; creation filter removes ancient noise
        "order": "desc",
        "per_page": 30,
    })
    fetched = saved = 0
    for repo in data.get("items", []):
        fetched += 1
        item = {
            "id": f"github_repo_{repo['id']}",
            "platform": "github",
            "source": "github_search_repos",
            "title": repo["full_name"],
            "text": repo.get("description") or "",
            "author": repo["owner"]["login"],
            "timestamp": _ts(repo.get("updated_at")),
            "url": repo["html_url"],
            "metadata": {
                "keyword": keyword,
                "stars": repo.get("stargazers_count"),
                "forks": repo.get("forks_count"),
                "language": repo.get("language"),
                "topics": repo.get("topics", []),
                "created_at": repo.get("created_at"),
                "source_type": "repository",
            },
        }
        if _save_if_signal(item):
            saved += 1
    logger.info("repos '%s' — %d fetched, %d saved", keyword, fetched, saved)
    return fetched, saved


# ── Keyword: issues — vulnerability discussions ───────────────────────────────

def _search_issues(keyword: str) -> tuple[int, int]:
    data = _get(f"{_BASE}/search/issues", {
        "q": f"{keyword} type:issue",
        "sort": "updated",
        "order": "desc",
        "per_page": 30,
    })
    fetched = saved = 0
    for issue in data.get("items", []):
        fetched += 1
        item = {
            "id": f"github_issue_{issue['id']}",
            "platform": "github",
            "source": "github_search_issues",
            "title": issue["title"],
            "text": issue.get("body") or "",
            "author": issue["user"]["login"],
            "timestamp": _ts(issue.get("updated_at")),
            "url": issue["html_url"],
            "metadata": {
                "keyword": keyword,
                "state": issue.get("state"),
                "labels": [l["name"] for l in issue.get("labels", [])],
                "source_type": "issue",
            },
        }
        if _save_if_signal(item):
            saved += 1
    logger.info("issues '%s' — %d fetched, %d saved", keyword, fetched, saved)
    return fetched, saved


# ── Keyword: commits — suspicious commit messages ─────────────────────────────

def _search_commits(keyword: str) -> tuple[int, int]:
    data = _get(f"{_BASE}/search/commits", {
        "q": keyword,
        "sort": "committer-date",
        "order": "desc",
        "per_page": 30,
    })
    fetched = saved = 0
    for c in data.get("items", []):
        fetched += 1
        commit = c.get("commit", {})
        item = {
            "id": f"github_commit_{c['sha']}",
            "platform": "github",
            "source": "github_search_commits",
            "title": commit.get("message", "")[:200],
            "text": commit.get("message", ""),
            "author": (commit.get("author") or {}).get("name", ""),
            "timestamp": _ts((commit.get("author") or {}).get("date")),
            "url": c.get("html_url", ""),
            "metadata": {
                "keyword": keyword,
                "repo": c.get("repository", {}).get("full_name"),
                "source_type": "commit",
            },
        }
        if _save_if_signal(item):
            saved += 1
    logger.info("commits '%s' — %d fetched, %d saved", keyword, fetched, saved)
    return fetched, saved


# ── Vuln-research org issues — only security research orgs, only issues ───────

def _collect_org_issues(org: str) -> tuple[int, int]:
    """Collect open issues from vuln-research orgs — these are almost always signal."""
    data = _get(f"{_BASE}/search/issues", {
        "q": f"org:{org} type:issue",
        "sort": "updated",
        "order": "desc",
        "per_page": 30,
    })
    fetched = saved = 0
    for issue in data.get("items", []):
        fetched += 1
        item = {
            "id": f"github_org_issue_{issue['id']}",
            "platform": "github",
            "source": f"github_org_{org}",
            "title": issue["title"],
            "text": issue.get("body") or "",
            "author": issue["user"]["login"],
            "timestamp": _ts(issue.get("updated_at")),
            "url": issue["html_url"],
            "metadata": {
                "org": org,
                "state": issue.get("state"),
                "labels": [l["name"] for l in issue.get("labels", [])],
                "source_type": "org_issue",
            },
        }
        if _save_if_signal(item):
            saved += 1
    logger.info("org issues '%s' — %d fetched, %d saved", org, fetched, saved)
    return fetched, saved


# ── Entry points ──────────────────────────────────────────────────────────────

def run_once() -> None:
    for kw in GITHUB_KEYWORDS:
        for fn in (_search_repos, _search_issues, _search_commits):
            try:
                fn(kw)
            except Exception as e:
                logger.error("%s('%s') failed: %s", fn.__name__, kw, e)

    for org in GITHUB_VULN_ORGS:
        try:
            _collect_org_issues(org)
        except Exception as e:
            logger.error("org issues '%s' failed: %s", org, e)


def run_continuous() -> None:
    logger.info("GitHub collector started (interval=%ds)", GITHUB_POLL_INTERVAL)
    while True:
        try:
            run_once()
        except Exception as e:
            logger.error("GitHub collector cycle error: %s", e)
        time.sleep(GITHUB_POLL_INTERVAL)
