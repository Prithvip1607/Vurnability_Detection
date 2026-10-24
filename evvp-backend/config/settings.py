import os
from dotenv import load_dotenv

load_dotenv()


def _secret(name: str) -> str:
    """Credential from the environment; a value that is only a stray '# comment' counts as unset."""
    v = (os.getenv(name) or "").strip()
    return "" if v.startswith("#") else v

# ── Credentials ───────────────────────────────────────────────────────────────
REDDIT_CLIENT_ID     = os.getenv("REDDIT_CLIENT_ID", "")
REDDIT_CLIENT_SECRET = os.getenv("REDDIT_CLIENT_SECRET", "")
REDDIT_USER_AGENT    = os.getenv("REDDIT_USER_AGENT", "EVVP/1.0")
GITHUB_TOKEN         = _secret("GITHUB_TOKEN")

# ── Storage ───────────────────────────────────────────────────────────────────
DB_URL       = os.getenv("DB_URL", "")   # PostgreSQL DSN; empty = JSON fallback
BASE_DIR     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DATA_DIR = os.getenv("EVVP_RAW_DATA_DIR") or os.path.join(BASE_DIR, "raw_data")
DATA_DIR     = os.getenv("EVVP_DATA_DIR") or os.path.join(BASE_DIR, "data")
LOG_DIR      = os.getenv("EVVP_LOG_DIR") or os.path.join(BASE_DIR, "logs")

# ── Polling intervals (seconds) ───────────────────────────────────────────────
REDDIT_POLL_INTERVAL = int(os.getenv("REDDIT_POLL_INTERVAL", 300))
GITHUB_POLL_INTERVAL = int(os.getenv("GITHUB_POLL_INTERVAL", 600))
BLOG_POLL_INTERVAL   = int(os.getenv("BLOG_POLL_INTERVAL",   900))
NVD_POLL_INTERVAL    = int(os.getenv("NVD_POLL_INTERVAL",   3600))

# ── Rate limits ───────────────────────────────────────────────────────────────
GITHUB_REQUESTS_PER_HOUR = int(os.getenv("GITHUB_REQUESTS_PER_HOUR", 1500 if _secret("GITHUB_TOKEN") else 120))   # search API: 30/min authed, 10/min anon

# ── Pipeline thresholds ───────────────────────────────────────────────────────
MIN_SIGNAL_SCORE      = 8    # drop items below this
EXPLOIT_DEV_MIN_SCORE = 6
HIGH_CONF_MIN_SCORE   = 14
NOVELTY_LOOKBACK_DAYS = 30   # how far back to check for duplicate titles

# ── Reddit subreddits ─────────────────────────────────────────────────────────
SUBREDDITS = [
    "netsec", "cybersecurity", "hacking", "exploitdev",
    "bugbounty", "ReverseEngineering", "blueteamsec", "AskNetsec",
    "netsecstudents", "malware", "pwned", "redteamsec",
]

# ── GitHub search keywords ────────────────────────────────────────────────────
GITHUB_KEYWORDS = [
    "poc exploit", "proof of concept exploit", "exploit released", "working exploit",
    "unauthenticated rce", "unauth rce", "pre-auth rce", "remote code execution poc",
    "0day exploit", "zero day exploit", "zero-day poc",
    "use-after-free exploit", "heap overflow exploit", "memory corruption exploit",
    "privilege escalation exploit", "lpe exploit", "sandbox escape exploit",
    "kernel exploit poc", "container escape exploit",
    "auth bypass exploit", "authentication bypass poc",
    "actively exploited", "exploited in the wild", "exploit chain poc",
    "supply chain attack poc", "deserialization exploit",
]

# ── GitHub vuln-research orgs ─────────────────────────────────────────────────
GITHUB_VULN_ORGS = ["googleprojectzero", "projectdiscovery", "cisagov"]

# ── RSS / Blog feeds ──────────────────────────────────────────────────────────
RSS_FEEDS = [
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.bleepingcomputer.com/feed/",
    "https://www.darkreading.com/rss.xml",
    "https://www.securityweek.com/feed/",
    "https://krebsonsecurity.com/feed/",
    "https://googleprojectzero.blogspot.com/feeds/posts/default",
    "https://blog.projectdiscovery.io/rss/",
    "https://portswigger.net/research/rss",
    "https://unit42.paloaltonetworks.com/feed/",
    "https://www.microsoft.com/en-us/security/blog/feed/",
    "https://www.helpnetsecurity.com/feed/",
    "https://cyberscoop.com/feed/",
    "https://www.trendmicro.com/en_us/research.rss",
    "https://www.rapid7.com/blog/feed/",
    "https://www.crowdstrike.com/blog/feed/",
    "https://www.recordedfuture.com/feed",
    "https://www.zerodayinitiative.com/rss/published/",
    "https://seclists.org/rss/fulldisclosure.rss",
]

# ── NVD API ───────────────────────────────────────────────────────────────────
NVD_API_KEY       = _secret("NVD_API_KEY")
NVD_BASE_URL      = os.getenv("NVD_BASE_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
NVD_LOOKBACK_DAYS = 3   # fetch CVEs published in last N days

# ── Notifications ─────────────────────────────────────────────────────────────
# Slack / Discord webhook — POST JSON with a "text" field
WEBHOOK_URL      = os.getenv("WEBHOOK_URL", "")

# Email alerts (SMTP)
ALERT_EMAIL_TO   = os.getenv("ALERT_EMAIL_TO", "")
ALERT_EMAIL_FROM = os.getenv("ALERT_EMAIL_FROM", "evvp@localhost")
SMTP_HOST        = os.getenv("SMTP_HOST", "")
SMTP_PORT        = int(os.getenv("SMTP_PORT", 587))
SMTP_USER        = os.getenv("SMTP_USER", "")
SMTP_PASS        = os.getenv("SMTP_PASS", "")

# Only notify when signal score >= this AND severity in filter
NOTIFY_MIN_SCORE       = int(os.getenv("NOTIFY_MIN_SCORE", 14))
NOTIFY_SEVERITY_FILTER = set(os.getenv("NOTIFY_SEVERITY_FILTER", "CRITICAL,HIGH").split(","))

# ── CVE Trend Tracker ─────────────────────────────────────────────────────────
SPIKE_WINDOW_HOURS  = int(os.getenv("SPIKE_WINDOW_HOURS", 6))    # window to detect spike
SPIKE_THRESHOLD     = int(os.getenv("SPIKE_THRESHOLD", 3))       # mentions in window = trending
TREND_COOLDOWN_MINS = int(os.getenv("TREND_COOLDOWN_MINS", 60))  # re-alert cooldown


# ── Source trust (feeds the risk and zero-day scores) ────────────────────────
TRUST_LEVELS = ("authoritative", "high", "medium", "low", "early_signal")
TRUST_WEIGHT = {"authoritative": 100, "high": 80, "medium": 55, "early_signal": 40, "low": 30}
SOURCE_TYPES = ("rss", "atom", "api", "custom")
SOURCE_CATEGORIES = ("official", "vendor", "research", "news", "community")
INTERVAL_MIN, INTERVAL_MAX = 5, 1440            # minutes

# ── Dashboard / API ───────────────────────────────────────────────────────────
HIGH_RISK_THRESHOLD = 60                        # risk >= this counts as "high-risk"
ZERO_DAY_MIN_SCORE  = 45                        # confidence needed to be a candidate
API_CACHE_TTL       = int(os.getenv("EVVP_CACHE_TTL", 30))
API_TOKEN_ENV       = "EVVP_API_TOKEN"          # read at request time; empty = writes open
CORS_ORIGINS = [o.strip() for o in os.getenv(
    "EVVP_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if o.strip()]

# ── Enrichment feeds ──────────────────────────────────────────────────────────
KEV_URL = os.getenv("KEV_URL", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
EPSS_URL = os.getenv("EPSS_URL", "https://api.first.org/data/v1/epss")
GITHUB_API_URL = os.getenv("GITHUB_API_URL", "https://api.github.com").rstrip("/")
REDDIT_BASE_URL = os.getenv("REDDIT_BASE_URL", "https://www.reddit.com").rstrip("/")
TICK_SECONDS = int(os.getenv("EVVP_TICK_SECONDS", 30))      # how often collectors check which sources are due
KEV_TTL_HOURS = 6
USER_AGENT = "EVVP/2.0 (vulnerability-intelligence platform)"
# NVD public limit: 5 requests / rolling 30 s without an API key, 50 with one. Spacing requests keeps EVVP inside it.
NVD_MIN_INTERVAL = float(os.getenv("NVD_MIN_INTERVAL_SECONDS", 0.7 if _secret("NVD_API_KEY") else 6.5))
KEV_LOOKBACK_DAYS = int(os.getenv("EVVP_KEV_LOOKBACK_DAYS", 14))     # CISA KEV collector: ingest entries added within this many days
