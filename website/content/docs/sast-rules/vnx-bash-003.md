---
title: "VNX-BASH-003 – Missing set -euo pipefail in Bash Script"
description: "Detects Bash scripts with a valid shebang that do not contain 'set -euo pipefail' or equivalent error-handling options, causing silent failure propagation and undefined-variable bugs."
---

## Overview

This rule flags Bash and shell scripts that have a `#!/usr/bin/env bash` or `#!/bin/sh` shebang line but do not contain a `set -e` (or equivalent combined form such as `set -euo pipefail`) directive. The check applies only to files ending in `.sh` or `.bash` and skips any script that already enables errexit via any `set` invocation that includes the `-e` flag.

Without `set -e`, a script continues executing even when a command fails with a non-zero exit code. A failed `cp`, `curl`, or database migration command will be silently ignored and subsequent steps will operate on incomplete or incorrect state. Without `set -u`, any typo in a variable name expands to the empty string rather than producing an error, so `rm -rf "$MY_DIR/"` becomes `rm -rf "/"` if `MY_DIR` is unset. Without `pipefail`, a failing command early in a pipeline (`curl ... | jq ...`) is invisible because the pipeline exit code is taken from the last command only.

**Severity:** Medium | **CWE:** [CWE-755 – Improper Handling of Exceptional Conditions](https://cwe.mitre.org/data/definitions/755.html)

## Why This Matters

Silent failure in shell scripts is a common root cause of data loss, partial deployments, and security configuration mistakes. A deployment script that continues past a failed `gpg --verify` check may install a tampered artifact. A backup script that continues past a failed `tar` invocation may overwrite the previous backup with an empty file, believing the operation succeeded.

From a security perspective, scripts that silently swallow errors are particularly dangerous in CI/CD pipelines, bootstrap scripts, and container entrypoints. An attacker who can cause one step to fail — for example by removing a file, exhausting disk space, or providing malformed input — may be able to force the script into an unexpected code path where later security checks are skipped entirely, or where subsequent commands operate on attacker-controlled fallback values.

The `pipefail` option is especially important when scripts parse the output of external commands through pipes. Without it, a command injection attempt that causes the first stage of a pipeline to fail goes undetected while the rest of the pipeline continues to execute with potentially attacker-influenced output from a partial run.

## What Gets Flagged

```bash
# FLAGGED: real script (has shebang) but no set -euo pipefail
#!/usr/bin/env bash

DEPLOY_DIR="/opt/app"
cp -r ./dist "$DEPLOY_DIR"    # if this fails, script continues anyway
chown -R www-data "$DEPLOY_DIR"
systemctl restart app
```

```bash
# FLAGGED: using sh shebang, still no error handling
#!/bin/sh
wget https://example.com/package.tar.gz
tar xzf package.tar.gz
./install.sh
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
