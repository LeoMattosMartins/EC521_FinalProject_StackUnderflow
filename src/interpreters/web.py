import re

# Define vulnerability patterns grouped by category
VULNERABILITY_PATTERNS = {
    "XSS": {
        "Script Tags": r"<script\b[^>]*>.*?</script>",
        "JavaScript URLs": r"javascript\s*:",
        "Event Handlers": r"on\w+\s*=",
        "Data URIs in src": r"src\s*=\s*[\"']?\s*data:",
        "JavaScript in href": r"href\s*=\s*[\"']?\s*javascript:",
        "Iframe Tags": r"<iframe\b[^>]*>",
        "Object Tags": r"<object\b[^>]*>",
        "Embed Tags": r"<embed\b[^>]*>",
        "SVG Tags": r"<svg\b[^>]*>",
        "Img Tags": r"<img\b[^>]*>",
        "Alert Function": r"\balert\s*\(",
    },
    "Injection": {
        "SQL Injection": r"(?i)\b(UNION|SELECT|INSERT|DELETE|DROP|ALTER|TRUNCATE|UPDATE)\b",
        "Command Injection": r"(?i)\b(exec|execute|system|popen|shell_exec)\b|\||&&|;|\$\(|`",
    },
    "DOM-based": {
        "Eval Usage": r"\beval\s*\(",
        "Document Write": r"\bdocument\.write\s*\(",
        "InnerHTML Usage": r"\binnerHTML\s*=",
        "Location Manipulation": r"\bwindow\.location\s*=",
        "SetTimeout withString": r"setTimeout\s*\(\s*['\"`]",
        "SetInterval withString": r"setInterval\s*\(\s*['\"`]",
    },
}

def detect_vulnerabilities(file_path):
    """
    Detect XSS, Injection, and DOM-based vulnerabilities in a file.
    
    :param file_path: Path to the file to be scanned.
    :return: Dictionary of vulnerabilities grouped by category and type.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()

        vulnerabilities = {category: {} for category in VULNERABILITY_PATTERNS}

        for category, patterns in VULNERABILITY_PATTERNS.items():
            for vuln_type, pattern in patterns.items():
                matches = []
                for line_num, line in enumerate(lines, start=1):
                    if re.search(pattern, line, re.IGNORECASE | re.DOTALL):
                        matches.append(line_num)
                if matches:
                    vulnerabilities[category][vuln_type] = matches

        return vulnerabilities

    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return {}
    except Exception as e:
        print(f"An error occurred: {e}")
        return {}

# Example usage
if __name__ == "__main__":
    file_path = "../../examples/webpage.html"  # Replace with your file path
    detected = detect_vulnerabilities(file_path)
    
    if any(detected.values()):
        print("Potential vulnerabilities detected:")
        total_categories = sum(1 for cat in detected.values() if cat)
        print(f"Total Categories of Vulnerabilities: {total_categories}")
        
        for category, vulns in detected.items():
            if not vulns:
                continue
            print(f"\n--- {category} ({len(vulns)} types) ---")
            for idx, (vuln_type, line_numbers) in enumerate(vulns.items(), start=1):
                min_line = min(line_numbers)
                max_line = max(line_numbers)
                print(f"  {idx}. {vuln_type}: Lines {min_line}-{max_line} (Occurrences: {len(line_numbers)})")
    else:
        print("No vulnerabilities detected.")
