import requests
import re
from datetime import datetime
import json

def get_cybersecurity_questions():
    url = "https://api.stackexchange.com/2.3/questions"
    params = {
        "order": "desc",
        "sort": "votes",
        "tagged": "cybersecurity",
        "site": "stackoverflow",
        "pagesize": 10,
        "filter": "withbody"  # Includes question body
    }
    response = requests.get(url, params=params)
    response.raise_for_status()
    return response.json()['items']

def get_bulk_answers(question_ids):
    url = f"https://api.stackexchange.com/2.3/questions/{';'.join(map(str, question_ids))}/answers"
    params = {
        "order": "desc",
        "sort": "votes",
        "site": "stackoverflow",
        "filter": "!nNPvSNe7D9"  # Valid filter for answer details
    }
    response = requests.get(url, params=params)
    response.raise_for_status()
    return response.json()['items']

def format_data(questions, answers):
    answer_map = {}
    for answer in answers:
        # Extract code snippets from markdown body
        code_snippets = re.findall(r'```(.*?)```|<code>(.*?)</code>', 
                                  answer.get('body_markdown', ''), 
                                  re.DOTALL)
        # Flatten and clean snippets
        snippets = [snippet.strip() for group in code_snippets 
                    for snippet in group if snippet]

        answer_map.setdefault(answer['question_id'], []).append({
            "answer_id": answer['answer_id'],
            "is_accepted": answer.get('is_accepted', False),
            "score": answer.get('score', 0),
            "creation_date": datetime.fromtimestamp(answer['creation_date']).isoformat(),
            "body_markdown": answer.get('body_markdown', ''),
            "code_snippets": snippets,
            "author": {
                "display_name": answer['owner'].get('display_name', 'N/A'),
                "reputation": answer['owner'].get('reputation', 0),
                "profile_link": answer['owner'].get('link', '')
            }
        })
    
    return [{
        "url": q['link'],
        "title": q['title'],
        "question_id": q['question_id'],
        "posted_date": datetime.fromtimestamp(q['creation_date']).isoformat(),
        "answers": answer_map.get(q['question_id'], [])
    } for q in questions]

def main():
    try:
        questions = get_cybersecurity_questions()
        question_ids = [q['question_id'] for q in questions]
        answers = get_bulk_answers(question_ids)
        
        formatted_data = format_data(questions, answers)
        
        with open("cybersecurity_answers.json", "w", encoding="utf-8") as f:
            json.dump(formatted_data, f, indent=2, ensure_ascii=False)
            
        print(f"Successfully saved {len(formatted_data)} questions with answers")

    except requests.exceptions.HTTPError as e:
        print(f"HTTP Error: {e.response.status_code}")
        print(f"Response: {e.response.text}")
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()