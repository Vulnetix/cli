---
title: "VNX-NODE-010 – Node.js Path Traversal"
description: "Detects user input from req.params or req.query used to construct file paths with fs.readFile, createReadStream, or path.join, enabling directory traversal attacks."
---

## Overview

This rule detects file-system operations — `fs.readFile`, `fs.readFileSync`, `fs.createReadStream`, `path.join`, `path.resolve`, and `res.sendFile` — where the path argument is drawn directly from user-supplied request data (`req.params`, `req.query`). Without strict path validation, an attacker can supply a filename containing `../` sequences to traverse out of the intended directory and read arbitrary files on the server. This is CWE-22 (Improper Limitation of a Pathname to a Restricted Directory — Path Traversal).

**Severity:** High | **CWE:** [CWE-22 – Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)](https://cwe.mitre.org/data/definitions/22.html)

## Why This Matters

Path traversal allows an attacker to read any file that the Node.js process has permission to access — application source code, configuration files, environment variable files (`.env`), database credentials, private keys, and operating system files like `/etc/passwd`. In a cloud environment, this commonly leads to reading instance credentials from well-known paths.

The attack is simple: instead of requesting `/files/report.pdf`, an attacker sends `/files/../../../../etc/passwd` or URL-encodes the traversal as `%2e%2e%2f` to bypass naive string filtering. The `path.join` function does resolve `..` sequences, but it does not constrain the result to a specific directory — `path.join('/var/files', '../../etc/passwd')` legitimately returns `/etc/passwd`. Normalisation alone is not sufficient defence.

## What Gets Flagged

The rule matches lines where any of the path-construction or file-access indicators directly accept `req.params` or `req.query` as an argument.

```javascript
// FLAGGED: readFile with user-supplied filename
app.get('/download/:filename', (req, res) => {
  fs.readFile(req.params.filename, (err, data) => {
    res.send(data);
  });
});

// FLAGGED: path.join with user query parameter
app.get('/files', (req, res) => {
  const filePath = path.join('/var/uploads', req.query.path);
  res.sendFile(filePath);
});
```

An attacker requests `/files?path=../../../../etc/shadow` and the server reads the password hash file.

## Remediation

1. **Resolve the full path and verify it starts with your base directory.** This is the only reliable defence against traversal:

   ```javascript
   // SAFE: resolve and prefix-check to prevent traversal
   const path = require('path');
   const fs = require('fs');

   const BASE_DIR = path.resolve('/var/uploads');

   app.get('/files', (req, res) => {
     const userPath = req.query.path;
     const resolved = path.resolve(BASE_DIR, userPath);

     if (!resolved.startsWith(BASE_DIR + path.sep)) {
       return res.status(403).json({ error: 'Access denied' });
     }

     fs.readFile(resolved, (err, data) => {
       if (err) return res.status(404).json({ error: 'File not found' });
       res.send(data);
     });
   });
   ```

   Note the `+ path.sep` — this prevents a path like `/var/uploads-secret/file` from passing the check even though it starts with `/var/uploads`.

2. **Strip all path separators and traversal sequences from filenames.** Accept only the base filename, never a path with directory components:

   ```javascript
   // SAFE: strip everything except the filename
   const filename = path.basename(req.params.filename);
   if (filename !== req.params.filename) {
     return res.status(400).json({ error: 'Invalid filename' });
   }
   const fullPath = path.join(BASE_DIR, filename);
   ```

3. **Validate the filename against an allowlist pattern.** Only allow alphanumeric characters, hyphens, underscores, and a single dot:

   ```javascript
   // SAFE: allowlist validation
   const SAFE_FILENAME = /^[a-zA-Z0-9_\-]+\.[a-zA-Z0-9]+$/;
   if (!SAFE_FILENAME.test(req.params.filename)) {
     return res.status(400).json({ error: 'Invalid filename' });
   }
   ```

4. **Use `res.sendFile` with an explicit `root` option** — Express will then constrain the file path to that root automatically:

   ```javascript
   // SAFE: root option constrains the path
   app.get('/static/:file', (req, res) => {
     res.sendFile(req.params.file, {
       root: path.resolve('/var/public'),
       dotfiles: 'deny',
     });
   });
   ```

5. **Apply least privilege at the OS level.** Run the Node.js process as a dedicated user with read access only to the specific directories it needs. Mount file-serving directories read-only in Docker deployments.

## References

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)](https://cwe.mitre.org/data/definitions/22.html)
- [CAPEC-126: Path Traversal](https://capec.mitre.org/data/definitions/126.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [Express – res.sendFile root option](https://expressjs.com/en/api.html#res.sendFile)
- [Node.js path.resolve documentation](https://nodejs.org/api/path.html#pathresolvepaths)
- [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [MITRE ATT&CK T1083 – File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
