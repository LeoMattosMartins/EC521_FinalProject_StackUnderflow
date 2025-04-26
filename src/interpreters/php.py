import re

def find_php_vulnerabilities(code: str):
    """
    Analyzes PHP source code for common web vulnerabilities.

    Returns a list of tuples List[Tuple[int, str]]:
      - The line number (int) where the issue was found
      - A description (str) of the detected vulnerability
    """
    lines = code.split('\n')
    vulnerabilities = []
    csrf_line = None
    has_csrf = False

    # Track variables holding user input
    user_input_vars = set()

    for lineNum, line in enumerate(lines, 1):
        stripped = line.strip()

        # === Track user input variables ===
        m_input = re.search(r'\$(\w+)\s*=\s*\$_(POST|GET|REQUEST)', stripped, re.IGNORECASE)
        if m_input:
            user_input_vars.add(m_input.group(1))

        # === SQL Injection via concatenation ===
        if re.search(r'\$.*=\s*".*"\s*\.\s*\$\w+', stripped):
            var = re.search(r'\.\s*\$(\w+)', stripped).group(1)
            if var in user_input_vars:
                vulnerabilities.append((lineNum, f"SQL injection risk via variable '${var}'"))

        # === Direct use of $_POST/$_GET/$_REQUEST ===
        if re.search(r"\$_(POST|GET|REQUEST)\[", stripped):
            vulnerabilities.append((lineNum, "Direct use of user input without sanitization"))

        # === XSS via echo/print ===
        if re.search(r"\b(echo|print)\s*\$[\w\d]+", stripped):
            if "htmlspecialchars" not in code:
                vulnerabilities.append((lineNum, "Potential XSS vulnerability via direct output"))

        # === Plaintext password handling ===
        if re.search(r"\$password\s*=\s*\$_POST", stripped) and "password_hash" not in code:
            vulnerabilities.append((lineNum, "Plaintext password storage detected"))

        # === Track CSRF form line ===
        if re.search(r"<form", stripped, re.IGNORECASE):
            csrf_line = lineNum

        # === Check for CSRF token presence ===
        if re.search(r"_csrf", stripped, re.IGNORECASE):
            has_csrf = True

    # === Check for missing CSRF token in forms ===
    if csrf_line and not has_csrf:
        vulnerabilities.append((csrf_line, "Form detected without CSRF protection token"))

    return vulnerabilities
