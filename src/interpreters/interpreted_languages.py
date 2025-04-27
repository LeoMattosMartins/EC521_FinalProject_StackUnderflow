import re

def find_interpreted_vulnerabilities(code: str):
    """
    Analyzes code written in interpreted languages (Python, Ruby, PHP, JavaScript, etc.)
    for common vulnerabilities like arbitrary code execution, command injection,
    insecure temp file usage, etc.

    @param code A string containing the source code.
    @return A list of tuples List[Tuple[int, str]]:
        - The line number (int) where the issue was found
        - A description (str) of the detected vulnerability
    """
    findings = []
    lines = code.split('\n')

    # === Patterns ===
    eval_pattern = re.compile(r"eval\s*\(")
    exec_pattern = re.compile(r"exec\s*\(")
    compile_pattern = re.compile(r"compile\s*\(")
    pickle_loads_pattern = re.compile(r"pickle\.loads\s*\(")
    marshal_loads_pattern = re.compile(r"marshal\.loads\s*\(")
    os_system_pattern = re.compile(r"os\.system\s*\(")
    subprocess_pattern = re.compile(r"subprocess\.(call|Popen|run)\s*\(")
    open_pattern = re.compile(r"open\s*\(\s*(input\s*\(|sys\.argv|\w+\.get\()")
    os_path_join_pattern = re.compile(r"os\.path\.join\s*\([^)]*(input\s*\(|sys\.argv)")
    sensitive_info_pattern = re.compile(r"(API_KEY|SECRET_KEY|PRIVATE_KEY|PASSWORD|TOKEN)\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
    mktemp_pattern = re.compile(r"mktemp\s*\(")

    # === Line-by-line checks ===
    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue

        if eval_pattern.search(stripped):
            findings.append((idx, "Use of eval() - potential arbitrary code execution"))
        if exec_pattern.search(stripped):
            findings.append((idx, "Use of exec() - potential arbitrary code execution"))
        if compile_pattern.search(stripped):
            findings.append((idx, "Use of compile() - potential arbitrary code execution"))
        if pickle_loads_pattern.search(stripped):
            findings.append((idx, "Use of pickle.loads() - potential arbitrary code execution"))
        if marshal_loads_pattern.search(stripped):
            findings.append((idx, "Use of marshal.loads() - potential arbitrary code execution"))

        if os_system_pattern.search(stripped):
            findings.append((idx, "Use of os.system() - potential command injection"))
        if subprocess_pattern.search(stripped):
            findings.append((idx, "Use of subprocess.call/Popen/run() - potential command injection"))

        if open_pattern.search(stripped):
            findings.append((idx, "Potential path traversal - open() called on user input"))
        if os_path_join_pattern.search(stripped):
            findings.append((idx, "Potential path traversal - os.path.join() with user input"))

        if sensitive_info_pattern.search(stripped):
            findings.append((idx, "Hardcoded sensitive information detected (API_KEY, SECRET_KEY, etc.)"))

        if mktemp_pattern.search(stripped):
            findings.append((idx, "Use of mktemp() - consider safer mkstemp() instead"))

        if "open(" in stripped and not ("with open(" in stripped or ".close(" in stripped):
            findings.append((idx, "Possible resource leak - open() without with or explicit close()"))

    return findings
