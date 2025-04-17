import os
import json
import re
import html  # For HTML entity decoding

inputDirectory = "FullData"
outputDirectory = "ParsedData"
minCharacterLimit = 500

def clean_code_block(code):
    # 1. Decode HTML entities (e.g., &quot; → ", > → >)
    code = html.unescape(code)
    
    # 2. Remove leading/trailing whitespace and common markdown artifacts
    code = code.strip()
    code = re.sub(r'^\s*[\w-]+\s*\n', '', code)  # Remove language specifier (e.g., ```cpp)
    code = re.sub(r'[\r\n]+', '\n', code)        # Normalize line endings
    code = re.sub(r'[\t ]+\n', '\n', code)       # Remove trailing spaces on lines
    
    return code

def process_answers(item):
    processed_answers = []
    for answer in item.get("answers", []):
        body = answer.get("body", "")
        matches = re.findall(r'```([\s\S]*?)```', body, re.MULTILINE)
        
        for match in matches:
            cleaned_code = clean_code_block(match)
            
            if len(cleaned_code) >= minCharacterLimit:
                new_answer = answer.copy()
                new_answer["body"] = cleaned_code
                processed_answers.append(new_answer)
    
    return processed_answers

def process_files():
    os.makedirs(outputDirectory, exist_ok=True)
    
    for filename in os.listdir(inputDirectory):
        if not filename.endswith(".json"):
            continue
            
        input_path = os.path.join(inputDirectory, filename)
        base_name, ext = os.path.splitext(filename)
        output_filename = f"{base_name}_longcode{ext}"
        output_path = os.path.join(outputDirectory, output_filename)
        
        try:
            with open(input_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            processed_data = []
            for item in data:
                processed_answers = process_answers(item)
                if processed_answers:
                    new_item = {
                        "url": item["url"],
                        "title": item["title"],
                        "question_id": item["question_id"],
                        "posted_date": item["posted_date"],
                        "answers": processed_answers
                    }
                    processed_data.append(new_item)
            
            if processed_data:
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(processed_data, f, indent=2)
                print(f"Processed {filename} → {output_filename}: {sum(len(item['answers']) for item in processed_data)} code blocks")
            else:
                print(f"Processed {filename}: No valid code blocks found")
        
        except Exception as e:
            print(f"Error processing {filename}: {str(e)}")

if __name__ == "__main__":
    process_files()