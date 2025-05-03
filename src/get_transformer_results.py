import os
import json
import torch
from transformers import RobertaTokenizer, RobertaForSequenceClassification
from tqdm import tqdm

MODEL_DIR    = "fine_tuned_codebert4"   
INPUT_DIR    = "Stack_Overflow_Datasets" 
OUTPUT_FILE  = "transformer_results2.json"            
LABEL_DICT = {
    "SQL Injection": 1,
    "XSS": 2,
    "Command Injection": 3,
    "Path Traversal": 4,
    "LDAP Injection": 5,
    "Code Injection": 6,
    "XPath Injection": 7,
    "OS Commanding": 8,
    "Buffer Overflow": 9,
    "Memory Leak": 10,
    "Memory Corruption": 11,
    "Sensitive Information": 12,
    "eval": 13,
    "Arbitrary Code Execution": 14,
    "Encoding Error": 15,
    "Insecure Randomness": 16,
    "KeyError Crash": 17,
    "Code Execution": 18,
    "NullPointerException": 19,
    "DoS": 20,
    "fmt.Printf": 21,
    "ClassCastException": 22,
    "Resource Leak": 23,
    "Null Pointer Exception": 24,
    "Off by one": 25
}

LABEL_ID_TO_NAME = {v: k for k, v in LABEL_DICT.items()}
LABEL_ID_TO_NAME[0] = "Safe"


device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
tokenizer = RobertaTokenizer.from_pretrained(MODEL_DIR)
model     = RobertaForSequenceClassification.from_pretrained(MODEL_DIR)
model.to(device)
model.eval()
results = []
global_counts = {name: 0 for name in LABEL_ID_TO_NAME.values() if name != "Safe"}



for fname in os.listdir(INPUT_DIR):
    if not fname.lower().endswith(".json"):
        continue
    language = os.path.splitext(fname)[0] 
    path = os.path.join(INPUT_DIR, fname)
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    for entry in tqdm(data,
                      desc=f"Processing {language}",
                      unit="snippet"):
        url = entry.get("url", "")
        code = entry["answers"][0]["body"]  

        encoding = tokenizer(
            code,
            truncation=True,
            padding="max_length",
            max_length=512,
            return_tensors="pt"
        ).to(device)
        with torch.no_grad():
            logits = model(**encoding).logits
        pred_id = int(torch.argmax(logits, dim=-1).item())
        vuln   = LABEL_ID_TO_NAME[pred_id]
        unsafe = 0 if pred_id == 0 else 1
        results.append({
            "language": language,
            "Stack_Overflow_Link": url,
            "Vulnerabilities_found": vuln,
            "Unsafe": unsafe
        })

        if unsafe:
            global_counts[vuln] += 1

with open(OUTPUT_FILE, "w", encoding="utf-8") as out:
    json.dump(results, out, indent=2)

print("\nGLOBAL VULNERABILITY SUMMARY")
print("="*30)
for vuln, cnt in sorted(global_counts.items(),
                        key=lambda x: -x[1]):
    print(f"{vuln}: {cnt}")
