import re

"""
Analyzes source code (e.g., Python, Java) for common SQL injection vulnerabilities.

The function inspects each line of code using regex heuristics and basic tracking
to detect unsafe query construction patterns, unparameterized executions,
and use of user-supplied input in SQL statements.

@param code A string containing multiple lines of source code.
            Each line will be analyzed for potential SQL vulnerabilities.

@return A list of tuples List[Tuple[int, str]]:
    - The line number (int) where the issue was found
    - A description (str) of the detected vulnerability
"""

def find_sql_vulnerabilities(code: str):
    lines = code.split('\n')
    results = []

    # === REGEX PATTERNS ===

    # Tracks variables assigned from user input (e.g., Python's input(), request.args, Scanner.nextLine())
    user_input_pattern = re.compile(r'(\w+)\s*=\s*(input\(|request\.get\(|scanner\.nextLine\()')

    # SQL built via string concatenation: SELECT ... " + var + " ...
    sql_concat_pattern = re.compile(r'\b(SELECT|INSERT|UPDATE|DELETE)\b.*\+.*')

    # Python f-strings with embedded variables
    f_string_pattern = re.compile(r'f["\'].*\{.+\}.*["\']')

    # %-formatting in string literals
    percent_format_pattern = re.compile(r'["\'].*%\(?.+\).*["\']')

    # .format() usage on SQL strings
    format_pattern = re.compile(r'["\'].*\{.+\}.*["\']\s*\.format\s*\(')

    # .execute(...) with a single string argument (no parameters passed separately)
    execute_single_arg_pattern = re.compile(r'\.execute\s*\(\s*["\'].*["\']\s*\)')

    # Java Statement.executeQuery / executeUpdate with concatenation
    java_stmt_concat_pattern = re.compile(r'Statement\.(?:executeQuery|executeUpdate)\s*\(\s*".*"\s*\+\s*\w+')

    # exec() or Runtime.getRuntime().exec() on dynamic SQL
    exec_pattern = re.compile(r'\b(exec|execute)\s*\(\s*\w+\s*\)')

    # Track variables that receive user input
    user_input_vars = set()

    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()

        # === Track user input assignments ===
        m_input = user_input_pattern.search(stripped)
        if m_input:
            var_name = m_input.group(1)
            user_input_vars.add(var_name)

        # === SQL concatenation vulnerability ===
        if sql_concat_pattern.search(stripped):
            results.append((lineno, "Dynamic SQL via string concatenation – risk of SQL injection"))

        # === f-string vulnerability ===
        if f_string_pattern.search(stripped):
            results.append((lineno, "Use of f-string to build SQL query – risk of SQL injection"))

        # === %-formatting vulnerability ===
        if percent_format_pattern.search(stripped):
            results.append((lineno, "Use of %-formatting to build SQL query – risk of SQL injection"))

        # === .format() vulnerability ===
        if format_pattern.search(stripped):
            results.append((lineno, "Use of .format() to build SQL query – risk of SQL injection"))

        # === Unparameterized execute() call ===
        if execute_single_arg_pattern.search(stripped):
            results.append((lineno, "execute() called with a single string literal – missing parameterization"))

        # === Java Statement concatenation vulnerability ===
        if java_stmt_concat_pattern.search(stripped):
            results.append((lineno, "Statement.executeQuery with concatenated SQL string – risk of SQL injection"))

        # === exec() on dynamic SQL variable ===
        if exec_pattern.search(stripped):
            results.append((lineno, "Dynamic exec() invocation – possible execution of unsanitized SQL"))

        # === User input used directly in SQL ===
        for var in user_input_vars:
            # if a tracked input variable appears in a SQL context
            if re.search(rf'\b{var}\b', stripped) and any(k in stripped.lower() for k in ('select', 'insert', 'update', 'delete')):
                results.append((lineno, f"User-supplied input '{var}' used directly in SQL – risk of SQL injection"))
                break

    return results

