"""
GitHub ingestion — searches repos, issues, and commits for exploit/vuln signals.
Also monitors vulnerability-research org issues.
"""
import time
from datetime import datetime, timezone

import requests

from config.settings import (
    GITHUB_TOKEN, GITHUB_KEYWORDS, GITHUB_VULN_ORGS,
    GITHUB_REQUESTS_PER_HOUR, GITHUB_POLL_INTERVAL,
)
from pipeline.processor import process
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter
from utils.retry import retry

logger  = get_logger("ingestion.github")
_lim    = RateLimiter(GITHUB_REQUESTS_PER_HOUR)
_BASE   = "https://api.github.com"
_HDRS   = {
    "Accept": "application/vnd.github+json",
    **( {"Authorization": f"Bearer {GITHUB_TOKEN}"} if GITHUB_TOKEN else {} ),
}


@retry(max_attempts=3, base_delay=15.0, exceptions=(requests.RequestException,))
def _get(url: str, params: dict | None = None) -> dict | list:
    _lim.wait()
    r = requests.get(url, headers=_HDRS, params=params, timeout=20)
    if r.status_code == 403:
        reset = int(r.headers.get("X-RateLimit-Reset", time.time() + 60))
        wait  = max(reset - time.time(), 5)
        logger.warning("GitHub rate limit — sleeping %.0fs", wait)
        time.sleep(wait)
        r = requests.get(url, headers=_HDRS, params=params, timeout=20)
    r.raise_for_status()
    return r.json()


def _ts(val: str | None) -> str:
    return val or datetime.now(timezone.utc).isoformat()


def _search_repos(keyword: str) -> tuple[int, int]:
    data = _get(f"{_BASE}/search/repositories", {
        "q": f"{keyword} created:>2020-01-01",
        "sort": "updated", "order": "desc", "per_page": 30,
    })
    fetched = saved = 0
    for repo in data.get("items", []):
        fetched += 1
        item = {
            "id":       f"github_repo_{repo['id']}",
            "platform": "github",
            "source":   "github_repos",
            "title":    repo["full_name"],
            "text":     repo.get("description") or "",
            "author":   repo["owner"]["login"],
            "timestamp": _ts(repo.get("updated_at")),
            "url":      repo["html_url"],
            "metadata": {
                "keyword": keyword, "stars": repo.get("stargazers_count"),
                "forks": repo.get("forks_count"), "language": repo.get("language"),
                "topics": repo.get("topics", []), "source_type": "repository",
            },
        }
        if process(item):
            saved += 1
    logger.info("repos '%s' — %d/%d saved", keyword, saved, fetched)
    return fetched, saved


def _search_issues(keyword: str) -> tuple[int, int]:
    data = _get(f"{_BASE}/search/issues", {
        "q": f"{keyword} type:issue",
        "sort": "updated", "order": "desc", "per_page": 30,
    })
    fetched = saved = 0
    for issue in data.get("items", []):
        fetched += 1
        item = {
            "id":       f"github_issue_{issue['id']}",
            "platform": "github",
            "source":   "github_issues",
            "title":    issue["title"],
            "text":     issue.get("body") or "",
            "author":   issue["user"]["login"],
            "timestamp": _ts(issue.get("updated_at")),
            "url":      issue["html_url"],
            "metadata": {
                "keyword": keyword, "state": issue.get("state"),
                "labels": [l["name"] for l in issue.get("labels", [])],
                "source_type": "issue",
            },
        }
        if process(item):
            saved += 1
    logger.info("issues '%s' — %d/%d saved", keyword, saved, fetched)
    return fetched, saved


def _search_commits(keyword: str) -> tuple[int, int]:
    data = _get(f"{_BASE}/search/commits", {
        "q": keyword, "sort": "committer-date", "order": "desc", "per_page": 30,
    })
    fetched = saved = 0
    for c in data.get("items", []):
        fetched += 1
        commit = c.get("commit", {})
        item = {
            "id":       f"github_commit_{c['sha']}",
            "platform": "github",
            "source":   "github_commits",
            "title":    commit.get("message", "")[:200],
            "text":     commit.get("message", ""),
            "author":   (commit.get("author") or {}).get("name", ""),
            "timestamp": _ts((commit.get("author") or {}).get("date")),
            "url":      c.get("html_url", ""),
            "metadata": {
                "keyword": keyword,
                "repo": c.get("repository", {}).get("full_name"),
                "source_type": "commit",
            },
        }
        if process(item):
            saved += 1
    logger.info("commits '%s' — %d/%d saved", keyword, saved, fetched)
    return fetched, saved


def _collect_org_issues(org: str) -> tuple[int, int]:
    data = _get(f"{_BASE}/search/issues", {
        "q": f"org:{org} type:issue",
        "sort": "updated", "order": "desc", "per_page": 30,
    })
    fetched = saved = 0
    for issue in data.get("items", []):
        fetched += 1
        item = {
            "id":       f"github_org_issue_{issue['id']}",
            "platform": "github",
            "source":   f"github_org_{org}",
            "title":    issue["title"],
            "text":     issue.get("body") or "",
            "author":   issue["user"]["login"],
            "timestamp": _ts(issue.get("updated_at")),
            "url":      issue["html_url"],
            "metadata": {
                "org": org, "state": issue.get("state"),
                "labels": [l["name"] for l in issue.get("labels", [])],
                "source_type": "org_issue",
            },
        }
        if process(item):
            saved += 1
    logger.info("org '%s' issues — %d/%d saved", org, saved, fetched)
    return fetched, saved


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
    logger.info("GitHub ingestion started (interval=%ds)", GITHUB_POLL_INTERVAL)
    while True:
        try:
            run_once()
        except Exception as e:
            logger.error("GitHub cycle error: %s", e)
        time.sleep(GITHUB_POLL_INTERVAL)
