import requests
import json
import time

queries = [
    "exploit poc",
    "rce exploit",
    "vulnerability poc",
    "zero day exploit",
    "cve exploit",
    "privilege escalation exploit"
]

all_repos = []
MAX_TOTAL = 280   # 🎯 target size

for q in queries:
    print(f"Searching: {q}")
    
    url = f"https://api.github.com/search/repositories?q={q}&sort=stars&order=desc&per_page=50"
    
    try:
        response = requests.get(url)
        
        if response.status_code != 200:
            print("Error:", response.status_code)
            continue
        
        data = response.json()

        if "items" not in data:
            continue

        for repo in data["items"]:
            text = (repo.get("name", "") + " " + (repo.get("description") or "")).lower()

            if not text.strip():
                continue

            all_repos.append({
                "text": text
            })

            # 🔥 LIMIT CONTROL
            if len(all_repos) >= MAX_TOTAL:
                break

    except Exception as e:
        print("Error:", e)

    if len(all_repos) >= MAX_TOTAL:
        break

    time.sleep(2)

print("Collected GitHub:", len(all_repos))

# -----------------------------
# SAFE SAVE
# -----------------------------
file_path = "github_data.json"

with open(file_path, "w", encoding="utf-8") as f:
    json.dump(all_repos, f, indent=4)

print("Saved successfully:", file_path)