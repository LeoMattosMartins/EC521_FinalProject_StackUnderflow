import re
from typing import List, Tuple


def find_web_vulnerabilities(web_code: str) -> List[Tuple[int, str]]:
    """
    Analyzes web code (HTML, JavaScript) for common security vulnerabilities.

    @param web_code: A string containing multiple lines of web code.
                     Each line will be analyzed for potential vulnerabilities.

    @return: A list of tuples (line_number, description)
    """
    # === RAW PATTERNS (as before) ===
    raw_patterns = {
        "XSS": {
            "InnerHTML": (
                r"\binnerHTML\s*=\s*"
                r"(?!.*(?:DOMPurify\.sanitize|escape\(|encodeURIComponent\("
                r"|textContent|createElement|setAttribute|appendChild))"
            ),
            "Document Write": (
                r"\bdocument\.(?:write|writeln)\s*\(\s*"
                r"(?!.*(?:escape\(|encodeURIComponent\(|textContent|createElement))"
            ),
            "Eval": r"\beval\s*\(\s*(?!.*(?:JSON\.parse|Function\('return'\)))",
            "SetTimeout": r"\bsetTimeout\s*\(\s*['\"`]",
            "SetInterval": r"\bsetInterval\s*\(\s*['\"`]",
            "ExecScript": r"\bexecScript\s*\(",
        },
        "CSRF": {
            "Form Without CSRF": (
                r"<form[^>]*>(?!.*(?:csrf|_token|authenticity_token|X-CSRF-TOKEN))"
            ),
            "Unsafe Fetch Request": (
                r"\bfetch\s*\(\s*['\"`][^'\"`]*['\"`]\s*,\s*\{[^}]*\}\s*\)"
                r"(?!.*(?:X-CSRF-TOKEN|csrf-token|X-XSRF-TOKEN))"
            ),
            "Missing SameSite Cookie": (
                r"\bdocument\.cookie\s*=\s*['\"`][^'\"`]*['\"`](?!.*SameSite)"
            ),
        },
    }

    # === COMPILE PATTERNS ONCE ===
    patterns = {}
    for category, group in raw_patterns.items():
        patterns[category] = {}
        for name, pat in group.items():
            try:
                patterns[category][name] = re.compile(pat, re.IGNORECASE | re.DOTALL)
            except re.error as e:
                raise ValueError(
                    f"[find_web_vulnerabilities] Invalid regex for "
                    f"{category!r}/{name!r}: {e}"
                )

    results: List[Tuple[int, str]] = []

    # === SCAN LINE BY LINE ===
    for lineno, line in enumerate(web_code.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue  # skip empty lines

        for category, group in patterns.items():
            for vuln_name, regex in group.items():
                if regex.search(stripped):
                    results.append((lineno, f"{category}: {vuln_name} vulnerability"))

    return results
