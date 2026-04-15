---
title: "VNX-BASH-007 – Unquoted Command Substitution in Shell Script"
description: "Detects command substitutions using $(...) that are not wrapped in double-quotes, exposing the result to word splitting and glob expansion and enabling argument injection if the output is attacker-influenced."
---

## Overview

This rule flags lines in Bash and shell scripts (`.sh`, `.bash`, `.bats`) where a `$(...)` command substitution appears without enclosing double-quotes. The detection looks for `$(...)` that is not immediately preceded by a double-quote character and is not part of a variable assignment or another `$` expression. Lines that are commented out are excluded, as are lines where the command substitution is already quoted with `"$(..."`.

When command output is captured without double-quotes, the shell applies word splitting (splitting on whitespace or the current `IFS`) and glob expansion (expanding `*`, `?`, and `[...]` patterns) to the result before passing it to the enclosing command. A command that produces a filename with spaces, a path with glob characters, or newline-separated output will be split into multiple unexpected arguments.

If the output of the substituted command is at all influenced by attacker-controlled data — a filename from a directory listing, a value from a configuration file, or the output of a tool that processes user input — word splitting can turn that single value into multiple shell arguments, potentially injecting additional flags or operands.

**Severity:** Medium | **CWE:** [CWE-88 – Improper Neutralisation of Argument Delimiters in a Command](https://cwe.mitre.org/data/definitions/88.html)

## Why This Matters

Argument injection via unquoted command substitution is a common source of bugs in shell scripts, and it becomes a security issue whenever the substituted command's output can be influenced by an external party. Consider a script that passes the output of a `basename` or `git rev-parse` call into another command without quoting — an attacker who can create a file or branch with a specially crafted name containing spaces or shell metacharacters can inject extra arguments into the receiving command.

Real-world attacks of this form have been demonstrated in CI/CD pipelines where attacker-controlled branch names or tag names flow through shell scripts. GitHub Actions workflows that pass `${{ github.head_ref }}` or similar values into shell scripts are particularly vulnerable when the script then uses unquoted command substitutions that incorporate those values. ATT&CK T1059.004 covers Unix shell interpreter abuse including this injection class.

The fix is mechanical and has zero performance cost: simply add double-quotes around every `$(...)`. If the script genuinely needs to split the output of a command into an array, use `mapfile -t arr < <(command)` or `read -ra arr <<< "$(command)"` instead of relying on unquoted word splitting.

## What Gets Flagged

```bash
# FLAGGED: unquoted command substitution in assignment used in command
files=$(ls /tmp)
rm $files    # $files unquoted and subject to splitting/glob

# FLAGGED: unquoted $() passed directly to a command
chown $(id -u):$(id -g) /some/path

# FLAGGED: command substitution in test without quotes
if [ $(whoami) = "root" ]; then echo ok; fi
```

## Remediation

1. Always wrap `$(...)` in double-quotes: `"$(command)"`.
2. When you need the output split into an array, use `mapfile` or `read -ra` rather than relying on unquoted word splitting.
3. Enable ShellCheck in your editor and CI pipeline to catch unquoted substitutions automatically.
4. Prefer `[[ ]]` over `[ ]` for conditional tests — while quoting is still recommended, `[[ ]]` does not perform word splitting.

```bash
# SAFE: command substitution double-quoted
files="$(find /tmp -maxdepth 1 -name '*.log')"
echo "Found: $files"

# SAFE: owner assignment with quoted substitutions
chown "$(id -u)":"$(id -g)" /some/path

# SAFE: comparison with quoted substitution
if [ "$(whoami)" = "root" ]; then echo ok; fi

# SAFE: split into array explicitly instead of relying on word splitting
mapfile -t log_files < <(find /var/log -name "*.log")
for f in "${log_files[@]}"; do
    process "$f"
done
```

## References

- [CWE-88: Improper Neutralisation of Argument Delimiters in a Command](https://cwe.mitre.org/data/definitions/88.html)
- [ShellCheck SC2046 – Quote this to prevent word splitting](https://www.shellcheck.net/wiki/SC2046)
- [BashFAQ/050 – I'm trying to put a command in a variable, but the complex cases always fail](https://mywiki.wooledge.org/BashFAQ/050)
- [OWASP – Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [CAPEC-88: OS Command Injection](https://capec.mitre.org/data/definitions/88.html)
