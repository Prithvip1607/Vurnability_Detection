import feedparser
import json

# -----------------------------
# EXTENDED SECURITY RSS FEEDS
# -----------------------------

feeds = [
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.bleepingcomputer.com/feed/",
    "https://packetstormsecurity.com/files/rss.xml",
    "https://www.darkreading.com/rss.xml",
    "https://threatpost.com/feed/",
    "https://krebsonsecurity.com/feed/",
    "https://www.schneier.com/feed/",
    "https://portswigger.net/daily-swig/rss",
    "https://www.securityweek.com/feed/",
    "https://cyberscoop.com/feed/",
    "https://www.helpnetsecurity.com/feed/",
    "https://www.csoonline.com/index.rss"
]

# -----------------------------
# COLLECT DATA
# -----------------------------

blog_posts = []
seen = set()

for url in feeds:
    print(f"Fetching from {url}")
    
    try:
        feed = feedparser.parse(url)
        
        for entry in feed.entries:
            title = entry.get("title", "")
            summary = entry.get("summary", "")
            
            text = (title + " " + summary).strip().lower()
            
            # skip empty
            if not text:
                continue
            
            # remove duplicates
            key = text[:150]
            if key in seen:
                continue
            seen.add(key)
            
            blog_posts.append({
                "text": text,
                "source": "blog"
            })
    
    except Exception as e:
        print(f"Error with {url}: {e}")

# -----------------------------
# OUTPUT
# -----------------------------

print("Collected blog posts:", len(blog_posts))

with open("blog_data.json", "w") as f:
    json.dump(blog_posts, f, indent=4)