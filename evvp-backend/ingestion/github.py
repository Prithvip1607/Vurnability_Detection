"""
GitHub ingestion — searches repos, issues, and commits for exploit/vuln signals.
Also monitors vulnerability-research org issues.
"""
import time
from datetime import datetime, timezone

import requests

from config.settings import TICK_SECONDS
from config.settings import (
    GITHUB_TOKEN, GITHUB_KEYWORDS, GITHUB_VULN_ORGS,
    GITHUB_REQUESTS_PER_HOUR, GITHUB_POLL_INTERVAL,
)
from pipeline.processor import process
from source_manager import manager
from utils.audit import audit, EV_SOURCE_FETCH_FAIL
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter
from utils.retry import retry

logger  = get_logger("ingestion.github")
_lim    = RateLimiter(GITHUB_REQUESTS_PER_HOUR)
from config.settings import GITHUB_API_URL as _BASE
_HDRS   = {
    "Accept": "application/vnd.github+json",
    **( {"Authorization": f"Bearer {GITHUB_TOKEN}"} if GITHUB_TOKEN else {} ),
}


@retry(max_attempts=2, base_delay=5.0, exceptions=(requests.RequestException,))
def _get(url: str, params: dict | None = None) -> dict | list:
    _lim.wait()
    r = requests.get(url, headers=_HDRS, params=params, timeout=20)
    if r.status_code == 403:
        reset = int(r.headers.get("X-RateLimit-Reset", time.time() + 60))
        wait  = min(max(reset - time.time(), 5), 120)      # never block a worker for more than 2 minutes
        logger.warning("GitHub rate limit — sleeping %.0fs", wait)
        time.sleep(wait)
        r = requests.get(url, headers=_HDRS, params=params, timeout=20)
    r.raise_for_status()
    return r.json()


def _ts(val: str | None) -> str:
    return val or ""            # never invent an observation time; first-seen falls back to collection time


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
            "timestamp": _ts(repo.get("created_at") or repo.get("updated_at")),
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
            "timestamp": _ts(issue.get("created_at") or issue.get("updated_at")),
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
            "timestamp": _ts(issue.get("created_at") or issue.get("updated_at")),
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


def run_once(force: bool = False) -> None:
    if not manager.gate("builtin-github", force):
        return
    if not GITHUB_TOKEN:
        logger.warning("GITHUB_TOKEN is not set: GitHub search is limited to ~10 requests/minute. Set it in .env.")
    ok = failed = streak = 0
    last_error = ""
    for kw in GITHUB_KEYWORDS:
        for fn in (_search_repos, _search_issues, _search_commits):
            if streak >= 3:                                  # circuit breaker: GitHub is down/blocked — stop this cycle
                break
            try:
                fn(kw)
                ok += 1
                streak = 0
            except Exception as e:
                failed += 1
                streak += 1
                last_error = str(e)
                logger.error("%s('%s') failed: %s", fn.__name__, kw, e)
        if streak >= 3:
            logger.error("GitHub: 3 consecutive failures — aborting this cycle")
            break
    for org in GITHUB_VULN_ORGS if streak < 3 else []:
        try:
            _collect_org_issues(org)
            ok += 1
        except Exception as e:
            failed += 1
            last_error = str(e)
            logger.error("org issues '%s' failed: %s", org, e)
    if ok == 0 and failed:
        manager.mark_fetch("builtin-github", success=False, error=f"all GitHub queries failed: {last_error}")
        audit(EV_SOURCE_FETCH_FAIL, source="GitHub", source_id="builtin-github", error=last_error[:300])
    else:
        manager.mark_fetch("builtin-github", success=True, item_count=ok)


def run_continuous() -> None:
    logger.info("GitHub collector started (interval comes from the Source Manager)")
    while True:
        try:
            run_once()
        except Exception as e:
            logger.error("GitHub cycle error: %s", e)
        time.sleep(TICK_SECONDS)
