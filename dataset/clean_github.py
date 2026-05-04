import json

# -----------------------------
# LOAD DATA
# -----------------------------

with open("github_data.json", "r") as f:
    data = json.load(f)

cleaned = []
seen = set()

# -----------------------------
# CLEANING
# -----------------------------

for repo in data:
    text = repo.get("text", "").strip().lower()

    if not text:
        continue

    # remove very short entries
    if len(text) < 10:
        continue

    # remove duplicates (strong normalization)
    normalized = " ".join(text.split()[:25])
    if normalized in seen:
        continue
    seen.add(normalized)

    # -----------------------------
    # LABELING
    # -----------------------------

    if any(k in text for k in ["exploit", "poc", "rce", "zero day"]):
        label = "HIGH"
    elif any(k in text for k in ["vulnerability", "bug", "issue", "flaw"]):
        label = "MEDIUM"
    else:
        label = "LOW"

    cleaned.append({
        "text": text,
        "label": label
    })

print("After cleaning:", len(cleaned))

# -----------------------------
# CONTROL SIZE (IMPORTANT)
# -----------------------------

MAX_GITHUB = 300

high = [x for x in cleaned if x["label"] == "HIGH"]
medium = [x for x in cleaned if x["label"] == "MEDIUM"]
low = [x for x in cleaned if x["label"] == "LOW"]

# controlled selection (GitHub = HIGH heavy)
final_github = (
    high[:200] +
    medium[:70] +
    low[:30]
)

cleaned = final_github

print("Final controlled GitHub samples:", len(cleaned))

# distribution
counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
for item in cleaned:
    counts[item["label"]] += 1

print("Distribution:", counts)

# -----------------------------
# SAVE
# -----------------------------

with open("cleaned_github.json", "w") as f:
    json.dump(cleaned, f, indent=4)