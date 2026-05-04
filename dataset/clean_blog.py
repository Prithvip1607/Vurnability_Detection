import json

# -----------------------------
# LOAD DATA
# -----------------------------

with open("blog_data.json", "r", encoding="utf-8") as f:
    data = json.load(f)

cleaned = []
seen = set()

# -----------------------------
# KEYWORDS
# -----------------------------

strong_keywords = [
    "exploit", "rce", "poc", "zero-day", "0day",
    "remote code execution"
]

medium_keywords = [
    "vulnerability", "attack", "security flaw",
    "bug", "issue", "flaw"
]

# -----------------------------
# CLEANING
# -----------------------------

for post in data:
    text = post.get("text", "").strip().lower()

    # remove empty
    if not text:
        continue

    # remove very short entries
    if len(text) < 30:
        continue

    # remove duplicates
    normalized = " ".join(text.split()[:30])
    if normalized in seen:
        continue
    seen.add(normalized)

    # -----------------------------
    # LABELING (FIXED LOGIC)
    # -----------------------------

    if any(k in text for k in strong_keywords):
        label = "HIGH"
    elif any(k in text for k in medium_keywords):
        label = "MEDIUM"
    else:
        # 🔥 FIX: blogs default to MEDIUM, not LOW
        label = "MEDIUM"

    cleaned.append({
        "text": text,
        "label": label
    })

# -----------------------------
# OUTPUT
# -----------------------------

print("Cleaned blog samples:", len(cleaned))

counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
for item in cleaned:
    counts[item["label"]] += 1

print("Distribution:", counts)

# -----------------------------
# SAVE
# -----------------------------

with open("cleaned_blog.json", "w", encoding="utf-8") as f:
    json.dump(cleaned, f, indent=4)