import os
from dotenv import load_dotenv

load_dotenv()

# ── Credentials ───────────────────────────────────────────────────────────────
REDDIT_CLIENT_ID     = os.getenv("REDDIT_CLIENT_ID", "")
REDDIT_CLIENT_SECRET = os.getenv("REDDIT_CLIENT_SECRET", "")
REDDIT_USER_AGENT    = os.getenv("REDDIT_USER_AGENT", "EVVP/1.0")
GITHUB_TOKEN         = os.getenv("GITHUB_TOKEN", "")

# ── Storage ───────────────────────────────────────────────────────────────────
DB_URL       = os.getenv("DB_URL", "")   # PostgreSQL DSN; empty = JSON fallback
BASE_DIR     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DATA_DIR = os.path.join(BASE_DIR, "raw_data")

# ── Polling intervals (seconds) ───────────────────────────────────────────────
REDDIT_POLL_INTERVAL = int(os.getenv("REDDIT_POLL_INTERVAL", 300))
GITHUB_POLL_INTERVAL = int(os.getenv("GITHUB_POLL_INTERVAL", 600))
BLOG_POLL_INTERVAL   = int(os.getenv("BLOG_POLL_INTERVAL",   900))
NVD_POLL_INTERVAL    = int(os.getenv("NVD_POLL_INTERVAL",   3600))

# ── Rate limits ───────────────────────────────────────────────────────────────
GITHUB_REQUESTS_PER_HOUR = 200   # conservative; authenticated = 5000/hr

# ── Pipeline thresholds ───────────────────────────────────────────────────────
MIN_SIGNAL_SCORE      = 4    # drop items below this
EXPLOIT_DEV_MIN_SCORE = 4
HIGH_CONF_MIN_SCORE   = 10
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
NVD_API_KEY       = os.getenv("NVD_API_KEY", "")
NVD_BASE_URL      = "https://services.nvd.nist.gov/rest/json/cves/2.0"
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
