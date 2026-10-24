import json

# -----------------------------
# KEYWORDS
# -----------------------------

strong_keywords = [
    "exploit", "rce", "poc", "overflow",
    "zero-day", "0day", "unauth", "pre-auth",
    "code execution", "remote execution"
]

medium_keywords = [
    "vulnerability", "bug", "issue", "flaw",
    "attack", "security", "exposed"
]

exclude_keywords = [
    "course", "newsletter", "learn", "career",
    "how to", "guide", "question", "advice",
    "recommend", "platform"
]

# -----------------------------
# LOAD DATA
# -----------------------------

with open("reddit_data.json", "r") as f:
    data = json.load(f)

cleaned = []
seen = set()

# -----------------------------
# CLEANING
# -----------------------------

for post in data:
    text = post.get("text", "").strip().lower()

    # remove empty / deleted
    if not text:
        continue
    if "[removed]" in text or "[deleted]" in text:
        continue

    # remove too short / too long
    if len(text) < 20 or len(text) > 1000:
        continue

    # remove obvious noise
    if any(k in text for k in exclude_keywords):
        continue

    # must contain security signal
    if not any(k in text for k in strong_keywords + medium_keywords):
        continue

    # remove duplicates (stronger normalization)
    normalized = " ".join(text.split()[:30])
    if normalized in seen:
        continue
    seen.add(normalized)

    # -----------------------------
    # LABELING
    # -----------------------------

    score = 0

    for k in strong_keywords:
        if k in text:
            score += 2

    for k in medium_keywords:
        if k in text:
            score += 1

    if score >= 3:
        label = "HIGH"
    elif score == 2:
        label = "MEDIUM"
    else:
        label = "LOW"

    cleaned.append({
        "text": text,
        "label": label
    })

print("After cleaning:", len(cleaned))

# -----------------------------
# CONTROL SIZE (VERY IMPORTANT)
# -----------------------------

MAX_REDDIT = 400

high = [x for x in cleaned if x["label"] == "HIGH"]
medium = [x for x in cleaned if x["label"] == "MEDIUM"]
low = [x for x in cleaned if x["label"] == "LOW"]

# balanced selection
final_reddit = (
    high[:150] +
    medium[:150] +
    low[:100]
)

cleaned = final_reddit

print("Final controlled Reddit samples:", len(cleaned))

# distribution
counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
for item in cleaned:
    counts[item["label"]] += 1

print("Distribution:", counts)

# -----------------------------
# SAVE
# -----------------------------

with open("cleaned_reddit_final.json", "w") as f:
    json.dump(cleaned, f, indent=4)