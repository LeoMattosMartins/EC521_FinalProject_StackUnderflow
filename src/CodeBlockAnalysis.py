import json
import os
import torch
from transformers import pipeline
from interpreters.web import find_web_vulnerabilities
from interpreters.c import find_c_vulnerabilities
from interpreters.sql import find_sql_vulnerabilities
from interpreters.php import find_php_vulnerabilities
from interpreters.interpreted_languages import find_interpreted_vulnerabilities
from collections import Counter
from tqdm import tqdm

# Check for CUDA availability
device = 0 if torch.cuda.is_available() else -1

# Zero-shot classifier
classifier = pipeline(
    "zero-shot-classification",
    model="facebook/bart-large-mnli",
    device=device,
)

directory = "../scrapper/ParsedData"
output_file = "vulnerabilities_reportV2.txt"

def is_code(body):
    return any(k in body for k in ["#", "include", "struct", "class", "def", "function", "{", "}"])

def run():
    # 1) Collect all snippets
    records = []
    for filename in os.listdir(directory):
        if not filename.endswith(".json"):
            continue
        path = os.path.join(directory, filename)
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        for item in data:
            url = item.get("url", "N/A")
            for ans in item.get("answers", []):
                body = ans.get("body", "")
                if is_code(body):
                    records.append({
                        "body": body,
                        "url": url,
                        "filename": filename,
                        "answer_id": ans["answer_id"],
                    })

    print(f"Collected {len(records)} code snippets.")

    # 2) Batched classification with progress bar
    labels = ["c", "c++", "javascript", "php", "sql", "html", "python", "ruby", "go"]
    batch_size = 32
    num_batches = (len(records) + batch_size - 1) // batch_size

    for i in tqdm(range(0, len(records), batch_size), desc="Classifying batches", total=num_batches):
        batch = records[i : i + batch_size]
        bodies = [r["body"] for r in batch]
        results = classifier(bodies, labels, multi_label=False)
        if isinstance(results, dict):
            results = [results]
        for rec, res in zip(batch, results):
            rec["predicted_language"] = res["labels"][0].lower()

    # 3) Vulnerability scanning & report writing with progress bar
    vuln_counter = Counter()
    with open(output_file, 'w', encoding='utf-8') as out:
        for rec in tqdm(records, desc="Scanning snippets"):
            lang = rec.get("predicted_language", "")
            url = rec["url"]
            body = rec["body"]
            findings = []

            # HTML/JS path
            if lang in ("html", "javascript"):
                for ln, desc in find_web_vulnerabilities(body):
                    findings.append(f"{desc} (line {ln})")
                    vuln_counter[desc] += 1

            # C/C++ path
            elif lang in ("c", "c++"):
                for ln, desc in find_c_vulnerabilities(body):
                    findings.append(f"{desc} (line {ln})")
                    vuln_counter[desc] += 1

            # SQL path
            elif lang == "sql":
                for ln, desc in find_sql_vulnerabilities(body):
                    findings.append(f"{desc} (line {ln})")
                    vuln_counter[desc] += 1

            # PHP path
            elif lang == "php":
                for ln, desc in find_php_vulnerabilities(body):
                    findings.append(f"{desc} (line {ln})")
                    vuln_counter[desc] += 1

            # Other interpreted languages
            elif lang in ("python", "ruby", "go"):
                for ln, desc in find_interpreted_vulnerabilities(body):
                    findings.append(f"{desc} (line {ln})")
                    vuln_counter[desc] += 1

            # Write findings if any
            if findings:
                out.write(f"Stack Overflow URL: {url}\n")
                for f in findings:
                    out.write(f"  - {f}\n")
                out.write("\n" + "="*80 + "\n\n")
                out.flush()

        # Global summary
        out.write("GLOBAL VULNERABILITY SUMMARY\n" + "="*30 + "\n")
        for t, cnt in vuln_counter.most_common():
            out.write(f"{t}: {cnt}\n")

    # Console summary
    print("Global vulnerability totals:")
    for t, cnt in vuln_counter.most_common():
        print(f"  {t}: {cnt}")

if __name__ == "__main__":
    run()
