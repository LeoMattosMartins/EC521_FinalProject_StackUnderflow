import requests
from datetime import datetime
import json
import time

# Replace these placeholders with your actual credentials
# TODO:Remove the Hardcoded credentials 
CLIENT_ID = ""
CLIENT_SECRET = ""
KEY = ""

# Validate credentials
if not all([CLIENT_ID, CLIENT_SECRET, KEY]):
    raise ValueError("Please provide valid CLIENT_ID, CLIENT_SECRET, and KEY.")

# TAGS: cybersecurity, c++, python, html, javascript, web, php, go, java
tagged = "java"  
max_pages = 500

def log(message):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")

def get_questions(page=1):
    url = "https://api.stackexchange.com/2.3/questions"
    params = {
        "order": "desc",
        "sort": "votes",
        "tagged": tagged,
        "site": "stackoverflow",
        "pagesize": 100,
        "page": page,
        "filter": "withbody",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "key": KEY
    }
    response = requests.get(url, params=params)
    response.raise_for_status()
    return response.json()

def get_answers(question_ids):
    url = f"https://api.stackexchange.com/2.3/questions/{';'.join(map(str, question_ids))}/answers"
    params = {
        "order": "desc",
        "sort": "votes",
        "site": "stackoverflow",
        "filter": "!nNPvSNe7D9",
        "pagesize": 100,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "key": KEY
    }
    response = requests.get(url, params=params)
    response.raise_for_status()
    return response.json()

def format_data(questions, answers):
    answer_map = {}
    for answer in answers:
        answer_map.setdefault(answer['question_id'], []).append({
            "answer_id": answer['answer_id'],
            "body": answer.get('body_markdown', ''),
            "score": answer.get('score', 0),
            "is_accepted": answer.get('is_accepted', False),
            "creation_date": datetime.fromtimestamp(answer['creation_date']).isoformat(),
            "author": answer['owner'].get('display_name', 'N/A')
        })
    
    return [{
        "url": q['link'],
        "title": q['title'],
        "question_id": q['question_id'],
        "posted_date": datetime.fromtimestamp(q['creation_date']).isoformat(),
        "answers": answer_map.get(q['question_id'], [])
    } for q in questions]

def main():
    all_questions = []
    all_answers = []
    page = 1
    has_more = True
    quota_remaining = float('inf')  # Start with a high number if unknown

    try:
        # Fetch questions
        while has_more and quota_remaining > 0 and page <= max_pages:
            log(f"Fetching questions page {page}...")
            q_data = get_questions(page)
            
            # Update quota from the response
            quota_remaining = q_data.get('quota_remaining', 0)
            log(f"  Quota remaining: {quota_remaining}")
            
            if not q_data['items']:
                log("No questions found for the given tag.")
                break
            
            all_questions.extend(q_data['items'])
            has_more = q_data.get('has_more', False)
            page += 1

            if quota_remaining <= 0:
                log("Quota exhausted while fetching questions.")
                break

        # Prepare question IDs in batches of 100
        question_ids = [q['question_id'] for q in all_questions]
        batches = [question_ids[i:i+100] for i in range(0, len(question_ids), 100)]

        # Fetch answers for all batches until quota runs out
        for i, batch in enumerate(batches, 1):
            if quota_remaining <= 0:
                log("Quota exhausted before fetching all answers.")
                break
                
            log(f"Processing answer batch {i}/{len(batches)} ({len(batch)} questions)")
            a_data = get_answers(batch)
            
            quota_remaining = a_data.get('quota_remaining', 0)
            log(f"  Quota remaining: {quota_remaining}")
            
            if not a_data['items']:
                log("No answers found for the given questions.")
                continue
            
            all_answers.extend(a_data['items'])

        # Format and save data
        formatted = format_data(all_questions, all_answers)
        
        with open(f"{tagged}_full_data.json", "w", encoding="utf-8") as f:
            json.dump(formatted, f, indent=2, ensure_ascii=False)

        log(f"Successfully saved {len(formatted)} questions with answers")

    except requests.exceptions.HTTPError as e:
        log(f"HTTP Error {e.response.status_code}: {e.response.json()}")
    except Exception as e:
        log(f"Unexpected error: {str(e)}")

if __name__ == "__main__":
    main()