import re
import sys

def php_file_analyze(file_path):
    with open(file_path, 'r', encoding = 'utf-8') as f:
        code = f.read()

    errors_found = []

    # Raw SQL queries
    sql_pattern = re.compile(r"(SELECT|INSERT|UPDATE|DELETE)\s+.*?\$(\w+)", re.IGNORECASE)
    if sql_pattern.search(code):
        errors_found.append("Possible SQL injection: the SQL query includes variables that are unsanitized or unprepared.")
    
    #Inputs of $_POST or $_GET directly
    input_pattern = re.compile(r"\$_(POST|GET|REQUEST)\[['\"](\w+)['\"]\]")
    if input_pattern.search(code):
        errors_found.append("User input accessed directly, validate or sanitize the input")

    #echo or print, possible XSS
    echo_pattern = re.compile(r"(echo|print)\s*\$\w+")
    if echo_pattern.search(code):
        errors_found.append("XSS vulnerability possible when user input is printed directly")

    #plaintext passwords instead of hashed ones
    if re.search(r"\$password\s*=\s*\$_POST", code) and "password_hash" not in code:
        errors_found.append("Plaintext password detected, consider using password_hash().")

    #check for absence of CSRF tokens 
    if '<form' in code and '_csrf' not in code:
        errors_found.append("Form detected without CSRF protection token.")

    if errors_found:
        print(f"Analysis of {file_path}:")
        for error in errors_found:
            print(" " + error)
    
    if __name__ == "__main__":
        if len(sys.argv) < 2:
            print("Usage: python php.py path/to/file.php")
        else:
            php_file_analyze(sys.argv[1])