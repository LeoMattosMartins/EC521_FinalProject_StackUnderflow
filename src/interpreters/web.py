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
        "Command Injection": r"(?i)\b(exec|execute|system|popen)\b|\||&&|;|`",
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


# In web.py (interpreters/web.py)
def detect_vulnerabilities(code):  # Changed from file_path to code
    """
    Detect vulnerabilities in a code string (not a file).
    """
    try:
        lines = code.splitlines()  # Split code into lines
        vulnerabilities = {category: {} for category in VULNERABILITY_PATTERNS}

        for category, patterns in VULNERABILITY_PATTERNS.items():
            for vuln_type, pattern in patterns.items():
                matches = []
                regex = re.compile(pattern, re.IGNORECASE | re.DOTALL)
                for line_num, line in enumerate(lines, start=1):
                    # skip HTML comments
                    if line.strip().startswith("<!--"):
                        continue
                    if regex.search(line):
                        matches.append(line_num)
                if matches:
                    vulnerabilities[category][vuln_type] = matches

        return vulnerabilities

    except Exception as e:
        print(f"An error occurred: {e}")
        return {}
