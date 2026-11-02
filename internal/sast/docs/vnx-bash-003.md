---
title: "VNX-BASH-003 – Failure Ignored in a Script Without set -e / set -u"
description: "In a shell script that does not enable errexit, reports an unchecked cd followed by a relative-path delete, an integrity check whose result nothing reads, and (without nounset) rm -r of a path built from a variable that can be empty."
---

## Overview

In an executable shell script (one with a sh/bash/dash/ksh/zsh shebang) that does not enable errexit (`set -e`, `set -o errexit`, a `-e` shebang flag or an `ERR` trap), this rule reports the three places where a silently ignored failure does damage: a bare `cd` or `pushd` that nothing checks (no `|| exit`, `&&`, `if` or `$?` test) followed within ten lines by a delete with a relative path (`rm ./*`, `rm -rf build`, `find . -delete`, `git clean -f`, `git reset --hard`); an integrity check (`sha256sum -c`, `gpg --verify`, `cosign verify`, `minisign -V`, `openssl dgst -verify`) run as a bare statement whose result nothing reads; and, when nounset is also off, `rm -r "$VAR/..."` where `VAR` can be empty (an unchecked positional parameter, an environment variable the script never sets, or a command-substitution result) with no `${VAR:?}`, default or `-z`/`-n` test. Not reported: scripts that enable errexit (and nounset, for the `rm` case), checked `cd` and checks, `cd` followed by non-destructive commands or absolute paths, a check that is the last command or a function's return value, sourced libraries without a shebang, test paths and `.bats` files. The mere absence of `set -euo pipefail` is not reported.

Without `set -e`, a script continues executing even when a command fails with a non-zero exit code. A failed `cp`, `curl`, or database migration command will be silently ignored and subsequent steps will operate on incomplete or incorrect state. Without `set -u`, any typo in a variable name expands to the empty string rather than producing an error, so `rm -rf "$MY_DIR/"` becomes `rm -rf "/"` if `MY_DIR` is unset. Without `pipefail`, a failing command early in a pipeline (`curl ... | jq ...`) is invisible because the pipeline exit code is taken from the last command only.

**Severity:** Medium | **CWE:** [CWE-755 – Improper Handling of Exceptional Conditions](https://cwe.mitre.org/data/definitions/755.html)

## Why This Matters

Silent failure in shell scripts is a common root cause of data loss, partial deployments, and security configuration mistakes. A deployment script that continues past a failed `gpg --verify` check may install a tampered artifact. A backup script that continues past a failed `tar` invocation may overwrite the previous backup with an empty file, believing the operation succeeded.

From a security perspective, scripts that silently swallow errors are particularly dangerous in CI/CD pipelines, bootstrap scripts, and container entrypoints. An attacker who can cause one step to fail — for example by removing a file, exhausting disk space, or providing malformed input — may be able to force the script into an unexpected code path where later security checks are skipped entirely, or where subsequent commands operate on attacker-controlled fallback values.

The `pipefail` option is especially important when scripts parse the output of external commands through pipes. Without it, a command injection attempt that causes the first stage of a pipeline to fail goes undetected while the rest of the pipeline continues to execute with potentially attacker-influenced output from a partial run.

## What Gets Flagged

```bash
#!/bin/bash
cd "$BUILD_DIR"                 # FLAGGED: if cd fails, the rm runs here
rm -rf ./*

sha256sum -c app.tar.gz.sha256  # FLAGGED: a failed check is ignored
tar -xzf app.tar.gz -C /opt/app

rm -rf "${CACHE_DIR}/"*         # FLAGGED: CACHE_DIR unset means rm -rf /*
```

Not flagged:

```bash
#!/bin/bash
set -euo pipefail
cd "$BUILD_DIR"
rm -rf ./*

cd "$BUILD_DIR" || exit 1
rm -rf "${CACHE_DIR:?}/"*
```

## Remediation

1. Add `set -euo pipefail` immediately after the shebang line in every Bash script.
2. For POSIX `sh` scripts (which lack `pipefail`), use `set -eu` as a minimum.
3. When you intentionally need to allow a command to fail, use the `|| true` idiom or a conditional rather than omitting the flag globally.
4. For commands where failure is expected, capture the exit code explicitly: `some_command || exit_code=$?`.

```bash
# SAFE: error handling enabled immediately after shebang
#!/usr/bin/env bash
set -euo pipefail

DEPLOY_DIR="/opt/app"

# Intentional fallback where failure is acceptable
mkdir -p "$DEPLOY_DIR" || true

cp -r ./dist "$DEPLOY_DIR"
chown -R www-data "$DEPLOY_DIR"
systemctl restart app
```

## References

- [CWE-755: Improper Handling of Exceptional Conditions](https://cwe.mitre.org/data/definitions/755.html)
- [ShellCheck SC2078 – set -e / errexit guidance](https://www.shellcheck.net/wiki/SC2078)
- [BashFAQ/105 – Why doesn't set -e (or set -o errexit) do what I expected?](https://mywiki.wooledge.org/BashFAQ/105)
- [OWASP Testing Guide – Testing for OS Command Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection)
- [Google Shell Style Guide – Error Handling](https://google.github.io/styleguide/shellguide.html#s7-naming-conventions)
