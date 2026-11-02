---
title: "VNX-BASH-004 – Unquoted Variable Used in Command or Test"
description: "Reports an unquoted expansion of a value the script's caller controls (a script-level positional parameter, or a variable assigned from one, from read or from OPTARG) used as a command argument or a [ ] / test operand, where word splitting and globbing turn it into extra arguments."
---

## Overview

This rule flags an unquoted expansion of a value the caller of the script controls, in shell scripts (`.sh`, `.bash`, `.ksh` and extensionless files with a sh/bash/dash/ksh shebang). The value is a script-level positional parameter (`$1`, `${2}`, `${1:-x}`, `$@`, `$*`) or a variable assigned from one, from `read`, from `OPTARG` or by `for x in "$@"` within the 80 lines above. It is reported where the shell splits and globs it: as an argument of a command, or as an operand of `[ ]` or `test`. Not reported: double-quoted expansions (including multi-line strings and quoted awk programs), `[[ ]]`, arithmetic, assignments, `case` words, special parameters (`$#`, `$?`, `$$`, `$!`), a function's own positional parameters, variables the script sets itself, `echo`/`printf`/`exit`/`return`/`shift` lines, here-document bodies, test paths and `.bats` files, and zsh scripts (zsh does not split unquoted parameters).

When a variable is unquoted inside `[ ]`, the shell performs word splitting on its value before passing it to the test command. A variable containing a space becomes two separate tokens, causing the test to receive the wrong number of arguments and behave unexpectedly or throw a syntax error. A value containing glob characters such as `*` or `?` triggers filename expansion, potentially matching unintended files from the working directory.

The security impact is more direct when the variable value is attacker-controlled. An adversary who can set a variable to a string with carefully placed spaces or shell metacharacters can manipulate conditional logic, bypass checks, or inject additional arguments into the test command.

**Severity:** Medium | **CWE:** [CWE-78 – Improper Neutralisation of Special Elements Used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)

## Why This Matters

Argument injection through word splitting is a subtle but serious vulnerability class in shell scripts. Unlike obvious command injections via `eval`, unquoted variable expansion attacks exploit the shell's own parsing rules. A file named `foo bar` in a directory, or an environment variable containing a space set by a malicious actor earlier in a pipeline, can silently change the logic of a security check.

Consider an access-control script that checks a username from an environment variable: if the username is `alice admin`, the unquoted test `[ $USERNAME = "alice" ]` becomes `[ alice admin = "alice" ]`, which is a syntax error — the check silently fails open or causes an unhandled exit depending on how errors are handled. Real-world CI/CD systems have been exploited through injected branch names or commit message content that ended up in shell variable comparisons without quoting.

ATT&CK technique T1059.004 covers Unix shell abuse, and CAPEC-88 describes argument injection — both are relevant here because exploiting this pattern can allow an attacker to alter the behaviour of security-relevant conditional checks in scripts.

## What Gets Flagged

```bash
target_dir=$1
rm -rf $target_dir              # FLAGGED: "a b" deletes ./a and ./b
cp $2 /var/backups/             # FLAGGED: positional parameter used unquoted
for f in "$@"; do mv $f /srv/archive/; done   # FLAGGED

read -r -p "Log directory: " logdir
find $logdir -name "*.log" -delete   # FLAGGED: read input split into arguments

name=$1
if [ -n $name ]; then ...         # FLAGGED: always true when $name is empty
```

Not flagged:

```bash
rm -rf "$target_dir"
if [[ -n $target && $target == release ]]; then ...
case $target in release) ;; esac
RSYNC_OPTS="-a --delete"; rsync $RSYNC_OPTS src dst   # set by the script itself
copy() { cp $1 /opt/; }            # a function's own argument
```

## Remediation

1. Always double-quote variable references inside `[ ]` tests: `[ "$var" = "value" ]`.
2. Prefer `[[ ]]` in Bash scripts — it does not perform word splitting or glob expansion on variable expansions, making it safer by default.
3. Enable `set -u` so that any reference to an unset variable is caught immediately rather than silently expanding to empty.
4. Use ShellCheck as part of your CI pipeline to catch unquoted variable usage automatically.

```bash
# SAFE: double-quoted variable in [ ] test
if [ "$username" = "admin" ]; then
    grant_access
fi

# SAFE: [[ ]] handles word splitting internally (Bash only)
if [[ $username == "admin" ]]; then
    grant_access
fi

# SAFE: quoted and using [[ ]] for file test
if [[ -f "$file_path" ]]; then
    process_file
fi
```

## References

- [CWE-78: Improper Neutralisation of Special Elements Used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
- [ShellCheck SC2086 – Double quote to prevent globbing and word splitting](https://www.shellcheck.net/wiki/SC2086)
- [BashFAQ/031 – Quoting variables in Bash](https://mywiki.wooledge.org/BashFAQ/031)
- [OWASP – Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [CAPEC-88: OS Command Injection](https://capec.mitre.org/data/definitions/88.html)
