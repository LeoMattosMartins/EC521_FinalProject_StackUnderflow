import json
import os
import torch
from transformers import pipeline
from interpreters.web import detect_vulnerabilities
from interpreters.c import find_c_vulnerabilities
from interpreters.sql import find_sql_vulnerabilities
from interpreters.php import find_php_vulnerabilities
from collections import Counter

# Check for CUDA availability
device = 0 if torch.cuda.is_available() else -1

# Zero-shot classifier
classifier = pipeline(
    "zero-shot-classification",
    model="facebook/bart-large-mnli",
    device=device,
)

directory = "../scrapper/ParsedData"
output_file = "vulnerabilities_report.txt"

def is_code(body):
    return any(k in body for k in ["#", "include", "struct", "class", "def", "function", "{", "}"])

def run():
    # 1) Collect all snippets
    records = []  # each: (body, url, filename, answer_id)
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

    # 2) Batched classification
    labels = ["c", "c++", "javascript", "php", "sql", "html"]
    batch_size = 32
    for i in range(0, len(records), batch_size):
        batch = records[i : i + batch_size]
        bodies = [r["body"] for r in batch]
        results = classifier(bodies, labels, multi_label=False)
        # ensure `results` is a list
        if isinstance(results, dict):
            results = [results]

        for rec, res in zip(batch, results):
            rec["predicted_language"] = res["labels"][0].lower()

    # 3) Vulnerability scanning & report writing
    vuln_counter = Counter()
    with open(output_file, 'w', encoding='utf-8') as out:
        for rec in records:
            lang = rec["predicted_language"]
            url = rec["url"]
            body = rec["body"]

            findings = []
            if lang in ["html", "javascript"]:
                vulns = detect_vulnerabilities(body)
                for cat in vulns.values():
                    for t, lines in cat.items():
                        for _ in lines:
                            findings.append(t)
                            vuln_counter[t] += 1

            elif lang in ["c", "c++"]:
                for ln, desc in find_c_vulnerabilities(body):
                    findings.append(desc)
                    vuln_counter[desc] += 1

            elif lang == "sql":
                for ln, desc in find_sql_vulnerabilities(body):
                    findings.append(desc)
                    vuln_counter[desc] += 1

            elif lang == "php":
                for ln, desc in find_php_vulnerabilities(body):
                    findings.append(desc)
                    vuln_counter[desc] += 1

            if findings:
                out.write(f"Stack Overflow URL: {url}\n")
                out.write("\n".join(f"Line _: {f}" for f in findings))
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
