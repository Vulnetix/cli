---
title: "VNX-BASH-004 – Unquoted Variable Used in Command or Test"
description: "Detects shell variables used inside single-bracket [ ] test expressions without double-quotes, making them vulnerable to word splitting, glob expansion, and argument injection."
---

## Overview

This rule flags lines in Bash or shell scripts (`.sh`, `.bash`) where a variable reference `$VAR` appears inside a single-bracket `[ ]` test expression without surrounding double-quotes. The rule specifically targets the older POSIX `[ ]` test construct rather than the Bash-extended `[[ ]]`, which handles word splitting internally. Lines that are commented out or that use `[[ ]]` are excluded.

When a variable is unquoted inside `[ ]`, the shell performs word splitting on its value before passing it to the test command. A variable containing a space becomes two separate tokens, causing the test to receive the wrong number of arguments and behave unexpectedly or throw a syntax error. A value containing glob characters such as `*` or `?` triggers filename expansion, potentially matching unintended files from the working directory.

The security impact is more direct when the variable value is attacker-controlled. An adversary who can set a variable to a string with carefully placed spaces or shell metacharacters can manipulate conditional logic, bypass checks, or inject additional arguments into the test command.

**Severity:** Medium | **CWE:** [CWE-78 – Improper Neutralisation of Special Elements Used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)

## Why This Matters

Argument injection through word splitting is a subtle but serious vulnerability class in shell scripts. Unlike obvious command injections via `eval`, unquoted variable expansion attacks exploit the shell's own parsing rules. A file named `foo bar` in a directory, or an environment variable containing a space set by a malicious actor earlier in a pipeline, can silently change the logic of a security check.

Consider an access-control script that checks a username from an environment variable: if the username is `alice admin`, the unquoted test `[ $USERNAME = "alice" ]` becomes `[ alice admin = "alice" ]`, which is a syntax error — the check silently fails open or causes an unhandled exit depending on how errors are handled. Real-world CI/CD systems have been exploited through injected branch names or commit message content that ended up in shell variable comparisons without quoting.

ATT&CK technique T1059.004 covers Unix shell abuse, and CAPEC-88 describes argument injection — both are relevant here because exploiting this pattern can allow an attacker to alter the behaviour of security-relevant conditional checks in scripts.

## What Gets Flagged

```bash
# FLAGGED: $username unquoted inside [ ] test
if [ $username = "admin" ]; then
    grant_access
fi

# FLAGGED: $file_path unquoted, glob expansion risk
if [ -f $file_path ]; then
    process_file
fi

# FLAGGED: unquoted $status in equality check
[ $status == "ok" ] && deploy
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
