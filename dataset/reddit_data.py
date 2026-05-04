import requests
import json
import time

subreddits = [
    "netsec",
    "cybersecurity",
    "hacking",
    "exploitdev",
    "security",
    "bugbounty"
]

keywords = [
    "exploit", "vulnerability", "rce",
    "poc", "overflow", "zero-day",
    "attack", "security flaw"
]

all_posts = []

for sub in subreddits:
    print(f"Fetching from {sub}")
    
    before = None
    
    for _ in range(15):  # increased pagination
        
        url = f"https://api.pullpush.io/reddit/search/submission/?subreddit={sub}&size=100"
        
        if before:
            url += f"&before={before}"
        
        response = requests.get(url)
        data = response.json().get("data", [])
        
        if not data:
            break
        
        for post in data:
            text = (post.get("title", "") + " " + post.get("selftext", "")).lower()
            
            if any(k in text for k in keywords):
                all_posts.append({
                    "text": text,
                    "subreddit": sub
                })
        
        before = data[-1]["created_utc"]
        time.sleep(1)

print("Collected Reddit:", len(all_posts))

with open("reddit_data.json", "w") as f:
    json.dump(all_posts, f, indent=4)