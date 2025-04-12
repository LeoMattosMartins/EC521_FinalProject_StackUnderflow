import requests
import json
from datetime import datetime
import os

# Replace these placeholders with your actual credentials
# TODO: Remove the Hardcoded credentials before sharing code
CLIENT_ID = ""
CLIENT_SECRET = ""
KEY = ""
tag = "java" # TAGS: cybersecurity, c++, python, html, javascript, web, php, go, java

# Validate credentials
if not all([CLIENT_ID, CLIENT_SECRET, KEY]):
    raise ValueError("Please provide valid CLIENT_ID, CLIENT_SECRET, and KEY.")


def getLowestUpVotes(page=1):
    url = "https://api.stackexchange.com/2.3/questions"
    params = {
        "order": "asc",
        "sort": "votes",
        "tagged": tag,
        "site": "stackoverflow",
        "pagesize": 1,
        "page": page,
        "filter": "!nNPvSNe7D9",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "key": KEY,
    }
    response = requests.get(url, params=params)
    response.raise_for_status()
    return response.json()


def main():
    # Get the lowest-voted cybersecurity question
    data = getLowestUpVotes()
    item = data["items"][0]

    # Extract relevant fields
    result = {
        "tag": tag,
        "title": item["title"],
        "link": item["link"],
        "score": item["score"],
        "closed_reason": item.get("closed_reason", "N/A"),
        "creation_date": datetime.fromtimestamp(item["creation_date"]).isoformat(),
    }

    # Read existing data if the file exists
    filename = "lowest_upvotes.json"
    if os.path.exists(filename):
        with open(filename, "r") as f:
            existing_data = json.load(f)
    else:
        existing_data = []

    # Append new result
    existing_data.append(result)

    # Write updated data back to file
    with open(filename, "w") as f:
        json.dump(existing_data, f, indent=4)


if __name__ == "__main__":
    main()
