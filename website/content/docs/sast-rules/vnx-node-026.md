---
title: "VNX-NODE-026 – Child process spawn with shell:true enables command injection"
description: "Detects Node.js spawn() or spawnSync() calls that use {shell:true}, which routes execution through a shell interpreter and enables injection of shell metacharacters from user-controlled arguments."
---

## Overview

This rule detects calls to `child_process.spawn()` or `child_process.spawnSync()` that include the option `shell: true`. When this option is set, Node.js executes the command via `/bin/sh -c` on Unix or `cmd.exe /d /s /c` on Windows, meaning the entire command string is interpreted by a shell before being executed. Shell metacharacters such as `;`, `&&`, `|`, `` ` ``, `$()`, `>`, and `<` take on special meaning in this context.

The key difference from `execFile()` is that `spawn()` by default accepts a separate argument array, giving it a similar safety profile — each argument is passed as a distinct parameter to the OS `execve()` call, bypassing the shell entirely. Setting `shell: true` throws away this separation and reintroduces all the risks of string-based shell execution. Any user-controlled data in the command string or argument array can then inject additional shell commands.

This is a subtle but serious footgun: developers often add `shell: true` to work around quoting issues or to enable shell features like environment variable expansion, without realising it opens a command injection path.

**Severity:** High | **CWE:** [CWE-78 – Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)

## Why This Matters

Command injection via `shell: true` has the same impact as any other OS command injection — arbitrary code execution with the privileges of the Node.js process. The risk is compounded because `spawn()` with `shell: true` is often used in code that is otherwise well-structured (using argument arrays), giving the false impression that it is safe.

In practice, even "safe-looking" argument arrays are not safe when `shell: true` is set. The shell receives the entire command line as a concatenated string and re-parses it, so a value like `; rm -rf /` in the argument array becomes a second shell command. Developers who rely on argument separation for safety are caught off guard when `shell: true` negates that protection.

CI/CD pipelines, developer tooling, and build systems are the highest-risk areas. These applications frequently invoke external commands and sometimes accept repository names, branch names, or user-provided parameters that are passed to those commands.

## What Gets Flagged

```javascript
// FLAGGED: shell:true routes through /bin/sh — metacharacters are interpreted
const { spawn } = require('child_process');
const proc = spawn('git', ['clone', userInput], { shell: true });

// FLAGGED: spawnSync with shell:true
const result = spawnSync('ls', [req.query.dir], { shell: true, encoding: 'utf8' });

// FLAGGED: child_process with shell:true in options
const child_process = require('child_process');
child_process.spawn('npm', ['run', req.body.script], { shell: true });
```

## Remediation

1. **Remove `shell: true`** and rely on the default `shell: false` behaviour, passing arguments as a separate array.

2. **Validate all user-supplied values** against a strict allowlist of permitted values before using them in any command.

3. **Use `execFile()` instead of `exec()`** for commands that do not need shell features — `execFile()` never uses a shell by default.

4. **If shell features are genuinely needed** (glob expansion, piping), perform those operations in Node.js code rather than delegating to the shell.

```javascript
// SAFE: shell:false (default) — arguments passed directly to the OS, no shell involved
const { spawn } = require('child_process');

app.post('/clone', (req, res) => {
  const repoName = req.body.repoName;

  // Validate against allowlist
  if (!/^[a-zA-Z0-9_-]+\/[a-zA-Z0-9_.-]+$/.test(repoName)) {
    return res.status(400).json({ error: 'Invalid repo name' });
  }

  const proc = spawn('git', ['clone', '--', `https://github.com/${repoName}.git`], {
    shell: false, // explicit and safe — this is also the default
    stdio: 'pipe',
  });

  proc.on('close', (code) => {
    res.json({ exitCode: code });
  });
});
```

## References

- [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
- [CAPEC-88: OS Command Injection](https://capec.mitre.org/data/definitions/88.html)
- [OWASP Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
- [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [Node.js child_process.spawn() documentation](https://nodejs.org/api/child_process.html#child_processspawncommand-args-options)
- [Node.js Security Best Practices – child processes](https://nodejs.org/en/docs/guides/security/)
