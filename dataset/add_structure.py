import json

# -----------------------------
# DICTIONARIES
# -----------------------------

vuln_types = {
    "rce": "RCE",
    "remote code execution": "RCE",
    "xss": "XSS",
    "sql injection": "SQLi",
    "sqli": "SQLi",
    "overflow": "Buffer Overflow",
    "uaf": "Use-After-Free",
    "use-after-free": "Use-After-Free"
}

targets = [
    "apache", "wordpress", "windows", "linux",
    "aws", "chrome", "nginx", "docker", "kubernetes"
]

attack_types = {
    "unauth": "unauth",
    "pre-auth": "pre-auth",
    "post-auth": "post-auth",
    "zero-day": "zero-day",
    "0day": "zero-day"
}

exploit_keywords = ["exploit", "poc"]

# -----------------------------
# LOAD DATA
# -----------------------------

with open("final_dataset.json", "r") as f:
    data = json.load(f)

structured_data = []

# -----------------------------
# PROCESSING
# -----------------------------

for item in data:
    text = item["text"].lower()

    # -------------------------
    # EXTRACT VULNERABILITY TYPE
    # -------------------------
    vulnerability_type = None
    for k in vuln_types:
        if k in text:
            vulnerability_type = vuln_types[k]
            break

    # -------------------------
    # EXTRACT TARGET SOFTWARE
    # -------------------------
    target_software = None
    for t in targets:
        if t in text:
            target_software = t
            break

    # -------------------------
    # EXTRACT ATTACK TYPE
    # -------------------------
    attack_type = None
    for k in attack_types:
        if k in text:
            attack_type = attack_types[k]
            break

    # -------------------------
    # CHECK EXPLOIT PRESENCE
    # -------------------------
    has_exploit = any(k in text for k in exploit_keywords)

    # -------------------------
    # BUILD STRUCTURED ITEM
    # -------------------------
    structured_item = {
        "text": item["text"],
        "label": item["label"],
        "source": item.get("source", None),
        "vulnerability_type": vulnerability_type,
        "target_software": target_software,
        "attack_type": attack_type,
        "has_exploit": has_exploit
    }

    structured_data.append(structured_item)

# -----------------------------
# OUTPUT
# -----------------------------

print("Total structured samples:", len(structured_data))

with open("final_structured_dataset.json", "w") as f:
    json.dump(structured_data, f, indent=4)