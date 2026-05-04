import json

with open("cleaned_reddit_final.json", "r") as f:
    reddit = json.load(f)

with open("cleaned_github.json", "r") as f:
    github = json.load(f)

with open("cleaned_blog.json", "r") as f:
    blog = json.load(f)

# add source if missing
for item in reddit:
    item["source"] = "reddit"

for item in github:
    item["source"] = "github"

for item in blog:
    item["source"] = "blog"

final = reddit + github + blog

print("Total dataset:", len(final))

with open("final_dataset.json", "w") as f:
    json.dump(final, f, indent=4)