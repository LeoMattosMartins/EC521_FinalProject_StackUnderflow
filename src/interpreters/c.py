import re

"""
Analyzes C source code for common memory and security vulnerabilities.

The function inspects each line of C code using regex heuristics and basic tracking
to detect issues like format-string vulnerabilities, memory mismanagement,
unsafe functions, and more.

@param c_code A string containing multiple lines of C source code.
      Each line will be analyzed for potential vulnerabilities.

@return A list of tuples List[Tuple[int, str]]:
    - The line number (int) where the issue was found
    - A description (str) of the detected vulnerability
"""

def find_c_vulnerabilities(c_code: str):
    lines = c_code.split('\n')
    freed_vars = set()
    malloc_vars = set()
    declared_vars = set()
    initialized_vars = set()
    results = []

    # === REGEX PATTERNS ===

    # Format string: printf(variable)  (no literal format string)
    format_string_pattern = re.compile(r'\bprintf\s*\(\s*([A-Za-z_]\w*)\s*\)')

    # malloc: ptr = malloc(...)
    malloc_pattern = re.compile(r'(\w+)\s*=\s*\w*\s*malloc\s*\(')

    # free: free(ptr);
    free_pattern = re.compile(r'free\s*\(\s*(\w+)\s*\)\s*;')

    # Dangerous functions: gets, strcpy, sprintf, scanf
    dangerous_function_pattern = re.compile(r'\b(gets|strcpy|sprintf|scanf)\b')

    # Variable declaration: int x; or float y = 0;
    declaration_pattern = re.compile(r'\b(int|float|char|double)\s+(\w+)')

    # NULL pointer dereference: *ptr = ... or if(ptr == NULL)
    null_deref_pattern = re.compile(r'\*\s*\w+.*NULL')

    # Unchecked input into integer: int x = scanf(...);
    integer_input_pattern = re.compile(r'\b(int|unsigned)\b.*=.*\b(scanf|input)\b')

    # Command injection: system(variable) or popen(variable)
    system_call_pattern = re.compile(r'\b(system|popen)\s*\(\s*\w+\s*\)')

    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        # === Format String Vulnerability ===
        if format_string_pattern.search(stripped):
            results.append((i, "Format-string vulnerability"))

        # === malloc tracking ===
        malloc_match = malloc_pattern.match(stripped)
        if malloc_match:
            var = malloc_match.group(1)
            malloc_vars.add(var)

        # === free tracking and double-free ===
        free_match = free_pattern.match(stripped)
        if free_match:
            var = free_match.group(1)
            if var in freed_vars:
                results.append((i, f"Double free of variable '{var}'"))
            else:
                freed_vars.add(var)

        # === Use-after-free ===
        for var in freed_vars:
            if re.search(rf'\b{var}\b', stripped) and not free_pattern.search(stripped):
                results.append((i, f"Use-after-free of variable '{var}'"))
                break

        # === Dangerous function usage ===
        dangerous_match = dangerous_function_pattern.search(stripped)
        if dangerous_match:
            func = dangerous_match.group(1)
            results.append((i, f"Dangerous function '{func}' may cause buffer overflow"))

        # === Variable declarations and initialization tracking ===
        decl_match = declaration_pattern.match(stripped)
        if decl_match:
            var = decl_match.group(2)
            declared_vars.add(var)
            if '=' in stripped:
                initialized_vars.add(var)

        # === Uninitialized variable usage ===
        tokens = re.findall(r'\b\w+\b', stripped)
        for var in tokens:
            if var in declared_vars and var not in initialized_vars:
                # assignment counts as initialization
                if re.match(rf'\b{var}\s*=', stripped):
                    initialized_vars.add(var)
                else:
                    results.append((i, f"Use of uninitialized variable '{var}'"))
                    break

        # === NULL pointer dereference ===
        if null_deref_pattern.search(stripped):
            results.append((i, "Possible NULL pointer dereference"))

        # === Integer overflow (heuristic) ===
        if integer_input_pattern.search(stripped):
            results.append((i, "Possible integer overflow from unchecked input"))

        # === Command injection ===
        if system_call_pattern.search(stripped):
            results.append((i, "Possible command injection via system/popen()"))

    return results
