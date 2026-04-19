---
title: "VNX-1037 – Process Injection"
description: "Detects use of OS process execution APIs across Go, Java, Node.js, PHP, Python, and Ruby that may allow command injection when input is not properly sanitised."
---

## Overview

VNX-1037 is an auto-generated broad-pattern rule that searches for OS process execution primitives across Go, Java, Node.js, PHP, Python, and Ruby source files. The rule targets `exec.Command` in Go, `Runtime` in Java, `child_process` in Node.js, `shell_exec` in PHP, `subprocess` in Python, and `system` in Ruby. These are associated with [CWE-1037](https://cwe.mitre.org/data/definitions/1037.html) in the rule metadata.

Note: CWE-1037 in MITRE's catalog covers "Processor Optimization Removal or Modification of Security-critical Code," which does not align with the intent of this rule. The rule is functionally a command injection detector, more accurately mapped to [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html) and the MITRE ATT&CK technique T1055 (Process Injection).

All flagged locations identify process execution APIs whose use is not inherently unsafe but requires careful validation of any user-controlled input passed as arguments.

**Severity:** Medium | **CWE:** [CWE-1037](https://cwe.mitre.org/data/definitions/1037.html) | **OWASP:** [A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/)

## Why This Matters

Command injection is consistently among the most critical vulnerability classes because it typically grants an attacker full control over the application host. When user-supplied data — query parameters, form fields, file names, API responses — reaches an OS process execution API without sanitisation, the attacker can execute arbitrary commands with the privileges of the application process.

Many developers believe parameterised argument arrays (e.g., `exec.Command("ls", userArg)`) are always safe, but shell=True equivalents and string concatenation into command builders remain common mistakes that bypass this protection.

## What Gets Flagged

The rule scans Go, Java, Node.js, PHP, Python, and Ruby source files for process execution patterns:

```python
# FLAGGED: Python subprocess with user input
import subprocess
subprocess.run(f"convert {filename}", shell=True)
```

```javascript
// FLAGGED: Node.js child_process
const { exec } = require('child_process');
exec(`git log ${userBranch}`, callback);
```

```go
// FLAGGED: Go exec.Command
cmd := exec.Command("bash", "-c", userInput)
cmd.Run()
```

## Remediation

1. Avoid shell interpolation entirely. Pass arguments as discrete array elements rather than building shell command strings.
2. In Python, use `subprocess.run([cmd, arg1, arg2], shell=False)` — never set `shell=True` with untrusted input.
3. In Go, pass each argument separately to `exec.Command("program", arg1, arg2)` rather than concatenating into a single string.
4. Validate and allowlist any user-controlled values that must be passed to subprocess calls.
5. Run application processes under a dedicated low-privilege account to limit the impact of exploitation.

## References

- [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [OWASP OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
- [MITRE ATT&CK T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
