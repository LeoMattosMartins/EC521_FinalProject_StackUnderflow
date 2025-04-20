import json
import os
import torch  # Add this import
from transformers import GPTNeoForCausalLM, GPT2Tokenizer

# Check for CUDA availability
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# Load model and tokenizer
model = GPTNeoForCausalLM.from_pretrained("EleutherAI/gpt-neo-1.3B").to(device)  # Move model to GPU
tokenizer = GPT2Tokenizer.from_pretrained("EleutherAI/gpt-neo-1.3B")

directory = "../scrapper/ParsedData"

def is_code(body):
    """Heuristic to check if text is code (imperfect)"""
    code_keywords = ["#", "include", "struct", "class", "def", "function", "{", "}"]
    return any(keyword in body for keyword in code_keywords)

def run():
    for filename in os.listdir(directory):
        if not filename.endswith(".json"):
            continue
            
        input_path = os.path.join(directory, filename)
        
        with open(input_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            for item in data:
                for answer in item.get("answers", []):
                    body = answer.get("body", "")
                    
                    # Skip non-code snippets
                    if not is_code(body):
                        continue
                        
                    # Create prompt
                    prompt = (
                        "Identify the programming language of this code snippet. "
                        "Choose from: c, c++, c#, java, python, javascript, ruby, php, sql, html, css.\n\n"
                        f"Code:\n{body}\n\nLanguage:"
                    )
                    
                    # Prepare inputs and move to GPU
                    inputs = tokenizer(prompt, return_tensors="pt").to(device)
                    
                    # Generate prediction
                    gen_tokens = model.generate(
                        **inputs,
                        max_length=1000,
                        num_return_sequences=1,
                        pad_token_id=tokenizer.eos_token_id
                    )
                    
                    # Decode and print results
                    gen_text = tokenizer.batch_decode(gen_tokens)[0]
                    print(f"File: {filename}, Answer ID: {answer['answer_id']}")
                    print(f"Prediction: {gen_text}\n")

if __name__ == "__main__":
    run()