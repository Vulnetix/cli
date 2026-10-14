---
title: "VNX-BASH-006 – Global IFS Reassignment in Shell Script"
description: "Reports an IFS change that escapes the code that needed it: a function that sets IFS without local IFS or a restore, a script-level IFS change never restored, export IFS, and IFS taken from a positional parameter or OPTARG."
---

## Overview

This rule reports an `IFS` change that escapes the code that needed it, in Bash scripts (`.sh`, `.bash` and extensionless files with a sh/bash/dash/ksh shebang): `IFS` assigned as a statement (`IFS=,` or `IFS=':'; read ...`) inside a function that never declares `local IFS` and never restores it before the function ends; `IFS` assigned at script level and not restored in the next 300 lines (no `IFS=$saved`, `IFS=$' \t\n'` or `unset IFS`); `export IFS`, which hands the separator to every child process; and `IFS` taken from a positional parameter or `OPTARG`. Not reported: a command-prefix assignment (`while IFS= read -r line`, `IFS=, read -r a b`), `IFS` set inside a subshell or command substitution, `local IFS`, an assignment that is later restored, the restore line itself, the strict-mode `IFS=$'\n\t'`, variables merely named like `IFS`, comments, strings, test paths and `.bats` files.

`IFS` controls the characters the shell uses to split unquoted variable expansions and the output of command substitutions into separate words. When `IFS` is changed globally, every subsequent expansion in the script is affected, even in parts of the code that have no awareness of the change. This creates a non-local, order-dependent side effect that is difficult to reason about and easy to misuse.

The security impact arises when global IFS manipulation changes how input strings are tokenised in a security-relevant context. A script that sets `IFS=":"` to parse a path list may inadvertently alter how a later command parses a filename, URL, or user-supplied value, leading to unexpected argument splitting or misinterpreted data.

**Severity:** Medium | **CWE:** [CWE-20 – Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

## Why This Matters

IFS manipulation bugs are subtle because they are non-local: the assignment might appear dozens of lines before the code it affects, and the effect only manifests when a variable contains the separator character. Scripts that work correctly in testing may fail in production when inputs happen to contain the modified separator.

From an attacker's perspective, if a script globally sets `IFS` to a character that also appears in attacker-controlled input — such as a comma in a CSV field or a colon in a URL — the attacker may be able to engineer situations where their input is split into unexpected tokens by subsequent shell operations. This can turn what appears to be a single string argument into multiple arguments, potentially injecting extra flags or values into subsequent commands.

A particularly dangerous pattern is a script that processes a list with a custom IFS and then passes an unsanitised value through a pipeline where the modified IFS causes unexpected splitting of what should be a single argument. CAPEC-15 (Catching Exception Throw/Signal from Privileged Block) and ATT&CK T1059.004 both relate to this class of shell behaviour manipulation.

## What Gets Flagged

```bash
split_fields() {
  IFS=,                 # FLAGGED: never restored, the caller's splitting changes
  set -- $1
}

IFS=$'\n'               # FLAGGED: script-level change, never restored
for f in $(find /var/log/app -name '*.log'); do gzip "$f"; done

export IFS=';'          # FLAGGED: every child process inherits it
IFS="$1"                # FLAGGED: the caller chooses the separator
```

Not flagged:

```bash
join_by() { local IFS="$1"; shift; echo "$*"; }
while IFS= read -r line; do echo "$line"; done < input.txt
joined=$(IFS=,; echo "${items[*]}")
OLDIFS="$IFS"; IFS=,; read -ra fields <<< "$CSV_LINE"; IFS="$OLDIFS"
set -euo pipefail; IFS=$'\n\t'
```

## Remediation

1. Use `local IFS=...` inside a function to restrict the scope of the change to that function only.
2. Use the `IFS=... read ...` pattern to set IFS for a single `read` invocation without affecting any other code.
3. Use `mapfile` or `readarray` for reading line-based data in Bash, which does not require IFS manipulation.
4. If global IFS must be changed, save the original value and restore it immediately after the operation that required the change.

```bash
# SAFE: local IFS scoped to a function
parse_csv_line() {
    local IFS=","
    read -ra fields <<< "$1"
    for field in "${fields[@]}"; do
        process "$field"
    done
}

# SAFE: IFS set only for the read invocation
while IFS="," read -r col1 col2 col3; do
    echo "$col1 $col2 $col3"
done < data.csv

# SAFE: save and restore if global change is unavoidable
OLD_IFS="$IFS"
IFS=","
# ... limited scope operations ...
IFS="$OLD_IFS"
```

## References

- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [ShellCheck SC2048 / IFS-related warnings](https://www.shellcheck.net/wiki/SC2048)
- [BashFAQ/001 – How to read a file line by line (and why IFS matters)](https://mywiki.wooledge.org/BashFAQ/001)
- [OWASP – Testing for Command Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection)
- [Bash Reference Manual – Word Splitting](https://www.gnu.org/software/bash/manual/bash.html#Word-Splitting)
