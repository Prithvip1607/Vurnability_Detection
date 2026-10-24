import os
from dotenv import load_dotenv

load_dotenv()

# Reddit API
REDDIT_CLIENT_ID = os.getenv("REDDIT_CLIENT_ID", "")
REDDIT_CLIENT_SECRET = os.getenv("REDDIT_CLIENT_SECRET", "")
REDDIT_USER_AGENT = os.getenv("REDDIT_USER_AGENT", "CyberThreatIntel/1.0")

# GitHub API
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")

# Database
DB_URL = os.getenv("DB_URL", "")  # PostgreSQL DSN; leave empty to use JSON fallback

# Storage
RAW_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "raw_data")

# Polling intervals (seconds)
REDDIT_POLL_INTERVAL  = int(os.getenv("REDDIT_POLL_INTERVAL",  300))
GITHUB_POLL_INTERVAL  = int(os.getenv("GITHUB_POLL_INTERVAL",  600))
BLOG_POLL_INTERVAL    = int(os.getenv("BLOG_POLL_INTERVAL",    900))

# Rate limiting — authenticated token allows 5000/hr; stay conservative
GITHUB_REQUESTS_PER_HOUR = 200

# Signal filtering
MIN_SIGNAL_SCORE = 6   # items scoring below this are dropped before storage

SUBREDDITS = [
    "netsec", "cybersecurity", "hacking", "exploitdev",
    "bugbounty", "ReverseEngineering", "blueteamsec", "AskNetsec",
]

# GitHub search queries — tightly scoped to exploit/vuln signals
# Each query is sent to /search/repositories, /search/issues, /search/commits
# Repos are sorted by `created` (not `updated`) to surface NEW activity
GITHUB_KEYWORDS = [
    # PoC / exploit releases
    "poc exploit",
    "proof of concept exploit",
    "exploit released",
    "working exploit",

    # RCE family
    "unauthenticated rce",
    "unauth rce",
    "pre-auth rce",
    "remote code execution poc",

    # Zero-day signals
    "0day exploit",
    "zero day exploit",
    "zero-day poc",

    # Memory corruption
    "use-after-free exploit",
    "heap overflow exploit",
    "memory corruption exploit",

    # Privilege / escape
    "privilege escalation exploit",
    "lpe exploit",
    "sandbox escape exploit",
    "kernel exploit poc",
    "container escape exploit",

    # Auth bypass
    "auth bypass exploit",
    "authentication bypass poc",

    # Active exploitation
    "actively exploited",
    "exploited in the wild",
    "exploit chain poc",
]

# GitHub orgs — only monitor their SECURITY-RESEARCH repos via issues/commits,
# NOT bulk repo dumps (org-level repo/event collection removed)
GITHUB_VULN_ORGS = [
    "googleprojectzero",   # pure vuln research
]

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
]
