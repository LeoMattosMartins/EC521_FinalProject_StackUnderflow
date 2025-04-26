import re

"""
Analyzes web code (HTML, JavaScript) for common security vulnerabilities.

The function inspects each line of web code using regex heuristics to detect
issues like XSS, injection attacks, and DOM-based vulnerabilities.

@param web_code A string containing multiple lines of web code.
      Each line will be analyzed for potential vulnerabilities.

@return A list of tuples List[Tuple[int, str]]:
    - The line number (int) where the issue was found
    - A description (str) of the detected vulnerability
"""

def find_web_vulnerabilities(web_code: str):
    lines = web_code.split('\n')
    results = []

    # === REGEX PATTERNS ===
    patterns = {
        "XSS": {
            "InnerHTML": r"\binnerHTML\s*=\s*(?!.*(?:DOMPurify\.sanitize|escape\(|encodeURIComponent\(|textContent|createElement|setAttribute|appendChild))",
            "Document Write": r"\bdocument\.(?:write|writeln)\s*\(\s*(?!.*(?:escape\(|encodeURIComponent\(|textContent|createElement))",
            "Eval": r"\beval\s*\(\s*(?!.*(?:JSON\.parse|Function\('return'\))",
            "SetTimeout": r"\bsetTimeout\s*\(\s*['\"`]",
            "SetInterval": r"\bsetInterval\s*\(\s*['\"`]",
            "ExecScript": r"\bexecScript\s*\(",
        },
        "CSRF": {
            "Form Without CSRF": r"<form[^>]*>(?!.*(?:csrf|_token|authenticity_token|X-CSRF-TOKEN))",
            "Unsafe Fetch Request": r"\bfetch\s*\(\s*['\"`][^'\"`]*['\"`]\s*,\s*\{[^}]*\}\s*\)(?!.*(?:X-CSRF-TOKEN|csrf-token|X-XSRF-TOKEN))",
            "Missing SameSite Cookie": r"\bdocument\.cookie\s*=\s*['\"`][^'\"`]*['\"`](?!.*SameSite)",
        }
    }

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # Check each category and pattern
        for category, vuln_patterns in patterns.items():
            for vuln_type, pattern in vuln_patterns.items():
                if re.search(pattern, stripped, re.IGNORECASE | re.DOTALL):
                    results.append((i, f"{category}: {vuln_type} vulnerability"))

    return results
