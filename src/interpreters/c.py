#!/usr/bin/env python3
import re
import sys
from collections import defaultdict

def remove_comments(line):
    # Remove single-line comments.
    return re.sub(r'//.*', '', line)

def compute_scopes(lines):
    """
    Compute scope boundaries (start and end line numbers) for blocks based on braces.
    Returns a dictionary mapping a scope tuple (e.g. ('global', 'block_3', ...)) to [start_line, end_line]
    and a list of scope tuples for each line indicating the active scopes.
    """
    scope_stack = ['global']
    scopes = {('global',): [1, len(lines)]}  # global scope covers entire file
    line_scopes = []

    block_counter = 0

    for lineno, line in enumerate(lines, start=1):
        clean_line = remove_comments(line)
        # Save the current scope for this line.
        line_scopes.append(tuple(scope_stack))
        for char in clean_line:
            if char == '{':
                block_counter += 1
                new_scope = f'block_{block_counter}_line_{lineno}'
                scope_stack.append(new_scope)
                scopes[tuple(scope_stack)] = [lineno, None]
            elif char == '}':
                if len(scope_stack) > 1:  # do not pop the global scope
                    current_scope = tuple(scope_stack)
                    scopes[current_scope][1] = lineno  # record end line
                    scope_stack.pop()
    return scopes, line_scopes

def parse_for_loop_declaration(line):
    """
    Look for a for-loop header and extract any variable declaration from it.
    Returns a list of (var_type, var_name) tuples.
    """
    vars_found = []
    for_match = re.search(r'\bfor\s*\(([^;]+);', line)
    if for_match:
        header = for_match.group(1)
        # Look for a declaration like: int i = 0  or  float j
        decl_pattern = re.compile(r'\b(int|float|double|char)\b\s+([^,)]+)')
        decl_match = decl_pattern.search(header)
        if decl_match:
            var_type = decl_match.group(1)
            var_decl = decl_match.group(2)
            var_decl = var_decl.strip().lstrip('*').strip()
            var_name = var_decl.split('=')[0].strip()
            if var_name:
                vars_found.append((var_type, var_name))
    return vars_found

def parse_normal_declarations(line):
    """
    Look for standard variable declarations (e.g., int a, b = 5;).
    Returns a list of (var_type, var_name) tuples.
    """
    vars_found = []
    pattern = re.compile(r'\b(int|float|double|char)\b\s+([^;]+);')
    match = pattern.search(line)
    if match:
        var_type = match.group(1)
        var_decls = match.group(2)
        for part in var_decls.split(','):
            part = part.strip().lstrip('*').strip()
            var_name = part.split('=')[0].strip()
            if '(' in var_name or ')' in var_name:
                continue
            if var_name:
                vars_found.append((var_type, var_name))
    return vars_found

def collect_declarations(lines, scopes, line_scopes):
    """
    Go through each line, extract variable declarations and record:
      - name, type, declared_line, scope (tuple), scope_end, and usage_count.
    """
    variables = []
    for idx, line in enumerate(lines):
        lineno = idx + 1
        clean_line = remove_comments(line)
        current_scope = line_scopes[idx]

        # Check for for-loop declarations.
        for_vars = parse_for_loop_declaration(clean_line)
        for var_type, var_name in for_vars:
            scope_end = scopes.get(tuple(current_scope), [lineno, len(lines)])[1]
            if scope_end is None:
                scope_end = len(lines)
            variables.append({
                "name": var_name,
                "type": var_type,
                "declared_line": lineno,
                "scope": current_scope,
                "scope_end": scope_end,
                "usage_count": 0
            })

        # Check for normal declarations.
        normal_vars = parse_normal_declarations(clean_line)
        for var_type, var_name in normal_vars:
            scope_end = scopes.get(tuple(current_scope), [lineno, len(lines)])[1]
            if scope_end is None:
                scope_end = len(lines)
            variables.append({
                "name": var_name,
                "type": var_type,
                "declared_line": lineno,
                "scope": current_scope,
                "scope_end": scope_end,
                "usage_count": 0
            })
    return variables

def count_variable_usage(lines, variables):
    """
    Count the number of times each variable is used in the file within its scope boundaries.
    For each token in a line, if it matches a declared variable name and falls within the scope
    boundaries, increment its count.
    """
    vars_by_name = defaultdict(list)
    for var in variables:
        vars_by_name[var["name"]].append(var)
    for var_list in vars_by_name.values():
        var_list.sort(key=lambda v: len(v["scope"]))

    for lineno, line in enumerate(lines, start=1):
        clean_line = remove_comments(line)
        for token in re.findall(r'\b\w+\b', clean_line):
            if token in vars_by_name:
                candidates = []
                for var in vars_by_name[token]:
                    if var["declared_line"] <= lineno <= var["scope_end"]:
                        candidates.append(var)
                if candidates:
                    chosen = max(candidates, key=lambda v: len(v["scope"]))
                    chosen["usage_count"] += 1
    return variables

def parse_function_definitions(lines):
    """
    Parse function definitions. Looks for lines that match a function definition signature.
    Returns a list of dictionaries with keys:
      - name: function name
      - declared_line: line number of definition
      - parameters: list of parameter strings (as extracted from inside the parentheses)
    This simple regex handles definitions that start with basic types (int, float, double, char, void)
    and assumes the opening brace is on the same line.
    """
    func_defs = []
    # Allow for optional "static" and similar qualifiers.
    pattern = re.compile(r'^\s*(?:static\s+)?(?:int|float|double|char|void)\s+(\w+)\s*\(([^)]*)\)\s*\{')
    for idx, line in enumerate(lines):
        lineno = idx + 1
        clean_line = remove_comments(line)
        match = pattern.search(clean_line)
        if match:
            func_name = match.group(1)
            params_str = match.group(2).strip()
            # Split parameters by comma, filtering out empty strings.
            parameters = [param.strip() for param in params_str.split(',') if param.strip()] if params_str else []
            func_defs.append({
                "name": func_name,
                "declared_line": lineno,
                "parameters": parameters
            })
    return func_defs

def parse_function_calls(lines, func_defs):
    """
    Parse function calls in the file.
    For each line (excluding those already recognized as definitions), we search for tokens
    that look like function calls. We ignore control structures (if, while, for, switch) and
    function definitions.
    Returns a list of dictionaries with keys:
      - name: function name called
      - used_line: the line number of the call
      - arguments: list of arguments as strings (split by commas)
    """
    func_calls = []
    # List of keywords to ignore.
    ignore_keywords = {'if', 'for', 'while', 'switch', 'return', 'sizeof'}
    # Pre-compile a simple pattern: word followed by '(' then capture everything until a ')'
    # Note: This will not correctly handle nested parentheses.
    pattern = re.compile(r'\b(\w+)\s*\(([^)]*)\)')
    # Create a set of function names that were defined.
    defined_funcs = {f["name"] for f in func_defs}
    for idx, line in enumerate(lines):
        lineno = idx + 1
        clean_line = remove_comments(line)
        # Skip lines that look like function definitions.
        if re.search(r'\b(?:int|float|double|char|void)\b\s+\w+\s*\([^)]*\)\s*\{', clean_line):
            continue
        # Search for potential function calls.
        for match in pattern.finditer(clean_line):
            func_name = match.group(1)
            # Ignore control keywords.
            if func_name in ignore_keywords:
                continue
            # We also might ignore C standard macros like printf if desired, but here we capture them.
            args_str = match.group(2).strip()
            arguments = [arg.strip() for arg in args_str.split(',') if arg.strip()] if args_str else []
            func_calls.append({
                "name": func_name,
                "used_line": lineno,
                "arguments": arguments
            })
    return func_calls

def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py file.c")
        sys.exit(1)

    file_path = sys.argv[1]
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
    except IOError as e:
        print(f"Error opening file: {e}")
        sys.exit(1)

    # Compute scopes for variables.
    scopes, line_scopes = compute_scopes(lines)
    variables = collect_declarations(lines, scopes, line_scopes)
    variables = count_variable_usage(lines, variables)

    # Parse function definitions and function calls.
    func_defs = parse_function_definitions(lines)
    func_calls = parse_function_calls(lines, func_defs)

    # Display variables.
    print("Variables found:")
    for var in variables:
        scope_str = " -> ".join(var["scope"])
        print(f"  {var['name']} (Type: {var['type']}), Declared at line {var['declared_line']}, "
              f"Scope: [{scope_str}], Usage count: {var['usage_count']}")

    print("\nFunction definitions:")
    for func in func_defs:
        params_str = ", ".join(func["parameters"]) if func["parameters"] else "None"
        print(f"  {func['name']} defined at line {func['declared_line']} with parameters: {params_str}")

    print("\nFunction calls:")
    for call in func_calls:
        args_str = ", ".join(call["arguments"]) if call["arguments"] else "None"
        print(f"  {call['name']} called at line {call['used_line']} with arguments: {args_str}")

if __name__ == "__main__":
    main()

