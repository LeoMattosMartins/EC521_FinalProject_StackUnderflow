import os
import json
import re

inputDirectory = "FullData"
outputDirectory = "ParsedData"
minCharacterLimit = 100

def extract_code_blocks(data):
    code_blocks = []
    for item in data:
        answers = item.get("answers", [])
        for answer in answers:
            body = answer.get("body", "")
            # Find all code blocks between triple backticks
            matches = re.findall(r'```([\s\S]*?)```', body)
            for match in matches:
                # Remove language specifier if present (e.g., ```c++)
                clean_code = re.sub(r'^\s*\w+\s*\n', '', match).strip()
                if len(clean_code) > 100:
                    code_blocks.append(clean_code)
    return code_blocks

def process_files():
    if not os.path.exists(outputDirectory):
        os.makedirs(outputDirectory)
    
    for filename in os.listdir(inputDirectory):
        if not filename.endswith(".json"):
            continue
            
        input_path = os.path.join(inputDirectory, filename)
        output_path = os.path.join(outputDirectory, filename)
        
        try:
            with open(input_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            code_blocks = extract_code_blocks(data)
            
            if code_blocks:
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(code_blocks, f, indent=2)
                print(f"Processed {filename}: Found {len(code_blocks)} code blocks")
            else:
                print(f"Processed {filename}: No valid code blocks found")
        
        except Exception as e:
            print(f"Error processing {filename}: {str(e)}")

if __name__ == "__main__":
    process_files()