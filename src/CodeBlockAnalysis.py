import json
import os
import torch
from transformers import GPTNeoForCausalLM, GPT2Tokenizer
from interpreters.web import detect_vulnerabilities  # HTML/JS interpreter
from interpreters.c import find_c_vulnerabilities  # New C interpreter

# Check for CUDA availability
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# Load model and tokenizer
model = GPTNeoForCausalLM.from_pretrained("EleutherAI/gpt-neo-1.3B").to(device)
tokenizer = GPT2Tokenizer.from_pretrained("EleutherAI/gpt-neo-1.3B")

directory = "../../scrapper/ParsedData"
output_file = "vulnerabilities_report.txt"

def is_code(body):
    code_keywords = ["#", "include", "struct", "class", "def", "function", "{", "}"]
    return any(keyword in body for keyword in code_keywords)

def run():
    with open(output_file, 'w', encoding='utf-8') as outfile:
        for filename in os.listdir(directory):
            if not filename.endswith(".json"):
                continue

            input_path = os.path.join(directory, filename)

            with open(input_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for item in data:
                    for answer in item.get("answers", []):
                        body = answer.get("body", "")

                        if not is_code(body):
                            continue

                        # Language detection prompt
                        prompt = (
                            "Identify the programming language of this code snippet. "
                            "Choose from: c, c++, c#, java, python, javascript, ruby, php, sql, html, css.\n\n"
                            f"Code:\n{body}\n\nLanguage:"
                        )

                        # Generate prediction
                        inputs = tokenizer(prompt, return_tensors="pt").to(device)
                        gen_tokens = model.generate(
                            **inputs,
                            max_length=50,
                            num_return_sequences=1,
                            pad_token_id=tokenizer.eos_token_id,
                        )
                        gen_text = tokenizer.batch_decode(gen_tokens)[0]
                        predicted_language = gen_text.strip().split("\n")[-1].strip().lower()

                        print(f"Processing: {filename} > Answer {answer['answer_id']}")
                        print(f"  Predicted Language: {predicted_language}")

                        # Vulnerability analysis
                        url = item.get("url", "N/A")
                        formatted_vulns = []

                        if predicted_language in ["html", "javascript"]:
                            vulnerabilities = detect_vulnerabilities(body)
                            for category, vuln_types in vulnerabilities.items():
                                for vuln_type, lines in vuln_types.items():
                                    for line in lines:
                                        formatted_vulns.append(f"Line {line}: {vuln_type}")

                        elif predicted_language == "c" or predicted_language == "c++":
                            c_vulns = find_c_vulnerabilities(body)
                            formatted_vulns = [f"Line {line}: {desc}" for line, desc in c_vulns]

                        # Write results if any vulnerabilities found
                        if formatted_vulns:
                            outfile.write(f"Stack Overflow URL: {url}\n")
                            outfile.write("\n".join(formatted_vulns))
                            outfile.write("\n" + "="*80 + "\n\n")

if __name__ == "__main__":
    run()