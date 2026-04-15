---
title: "VNX-NODE-022 – Shell injection via shelljs exec()"
description: "Detects shelljs exec() or shell.exec() called with a variable argument that may contain user-controlled data, enabling shell metacharacter injection and arbitrary command execution."
---

## Overview

This rule detects two patterns involving the `shelljs` library: any import of `shelljs` (as a warning prompting review), and any call to `.exec()` or `.execSync()` where the argument is a variable derived from request data or is otherwise non-literal. The `shelljs` library provides a Unix shell interface from Node.js, and its `exec()` function passes the command string directly to `/bin/sh`, which interprets shell metacharacters.

Unlike Node.js built-in `child_process.execFile()`, which accepts a command and arguments separately, `shelljs.exec()` accepts a single string that is evaluated by the shell. This means any unescaped user input in the string — semicolons, backticks, pipe characters, `$()` substitution — is interpreted as shell syntax rather than data.

Command injection via `shelljs` typically results in full remote code execution with the privileges of the Node.js process. In containerised or cloud environments where the application runs as root or with broad IAM permissions, the impact is amplified significantly.

**Severity:** Critical | **CWE:** [CWE-78 – Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)

## Why This Matters

Shell injection is one of the highest-impact vulnerabilities in web applications. An attacker who can control the argument to `shell.exec()` can read and exfiltrate any file on the server, modify system files, install persistent backdoors, pivot to internal network services, and exfiltrate cloud instance credentials via the metadata API.

`shelljs` is commonly used in build scripts, CLI tools, and developer utilities that are sometimes inadvertently exposed to user input — for example, a build API that accepts a repository name and passes it to a shell command, or a webhook handler that includes request body data in a shell command for processing.

The danger is compounded by the fact that escaping shell arguments correctly is notoriously error-prone. Even well-intentioned sanitisation often misses edge cases. The correct fix is to avoid the shell entirely by using `child_process.execFile()` or `child_process.spawn()` with `shell: false` and a separated argument array.

## What Gets Flagged

```javascript
// FLAGGED (warning): shelljs imported — review all exec() calls
const shell = require('shelljs');

// FLAGGED: exec() called with request-derived variable
app.post('/run', (req, res) => {
  const result = shell.exec('git clone ' + req.body.repoUrl);
  res.json({ output: result.stdout });
});

// FLAGGED: execSync with template literal containing user data
const output = shell.execSync(`ls ${req.query.path}`);
```

## Remediation

1. **Replace `shell.exec()` with `child_process.execFile()`** and pass the command and arguments as separate parameters so the shell is never involved.

2. **Use `child_process.spawn()` with `shell: false`** (the default) when streaming output is required.

3. **Validate user input against a strict allowlist** if it must inform the command — reject anything not matching the allowlist before using it.

4. **Uninstall `shelljs`** from production dependencies if it is only used in build/development scripts.

```javascript
// SAFE: use execFile() — no shell involved, arguments are not interpreted
const { execFile } = require('child_process');

app.post('/clone', (req, res) => {
  const repoUrl = req.body.repoUrl;

  // Validate against allowlist before use
  if (!/^https:\/\/github\.com\/[a-zA-Z0-9_-]+\/[a-zA-Z0-9_.-]+\.git$/.test(repoUrl)) {
    return res.status(400).json({ error: 'Invalid repository URL' });
  }

  execFile('git', ['clone', '--', repoUrl], { timeout: 30000 }, (err, stdout, stderr) => {
    if (err) return res.status(500).json({ error: 'Clone failed' });
    res.json({ output: stdout });
  });
});
```

## References

- [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
- [CAPEC-88: OS Command Injection](https://capec.mitre.org/data/definitions/88.html)
- [OWASP Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
- [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [shelljs npm package](https://www.npmjs.com/package/shelljs)
- [Node.js child_process.execFile() documentation](https://nodejs.org/api/child_process.html#child_processexecfilefile-args-options-callback)
