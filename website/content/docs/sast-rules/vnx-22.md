---
title: "VNX-22 – Path Traversal"
description: "Detect user-controlled data used in file path operations without normalisation or directory-boundary validation, enabling attackers to read or write files outside the intended directory."
---

## Overview

This rule flags two classes of path traversal indicator: literal traversal sequences (`../`, `..\`, `..%2f`, `..%5c`) embedded anywhere in source code, and file-access sinks (`open()`, `fs.readFile()`, `new File()`, `os.Open()`, etc.) that appear on the same line as recognisable user-input variable names. Path traversal allows an attacker to supply a crafted filename like `../../etc/passwd` or `..\Windows\System32\config\SAM` to escape the intended directory and read or overwrite sensitive files. This maps to [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html).

**Severity:** High | **CWE:** [CWE-22 – Path Traversal](https://cwe.mitre.org/data/definitions/22.html)

## Why This Matters

Path traversal is consistently ranked in the OWASP Top Ten and CWE Top 25 because it is easy to introduce and its impact is severe. Reading `/etc/shadow` or a private key file can lead directly to full system compromise. Writing to arbitrary paths enables configuration tampering, web-shell upload, or cron-job injection. Many real-world breaches — including major source-code leaks — began with a path traversal in a file-download endpoint. The encoded variants (`%2f` for `/`, `%5c` for `\`) exist because developers who filter the literal string `../` forget that web frameworks URL-decode input before it reaches application code.

## What Gets Flagged

```javascript
// FLAGGED: literal traversal sequence in source
const base = '/var/www/uploads/';
const file = base + '../../../etc/passwd';  // literal ../

// FLAGGED: user input flows into fs.readFile on the same line
app.get('/download', (req, res) => {
    fs.readFile('/uploads/' + req.query.filename, (err, data) => {
        res.send(data);
    });
});
```

```python
# FLAGGED: user input in open()
@app.route('/file')
def get_file():
    name = request.args['name']
    with open('/data/' + name) as f:   # name may contain ../
        return f.read()
```

```java
// FLAGGED: user input in new File()
String fileName = request.getParameter("file");
File f = new File("/uploads/" + fileName);
```

```php
<?php
// FLAGGED: user input in file_get_contents
$file = $_GET['doc'];
echo file_get_contents('/docs/' . $file);
```

```go
// FLAGGED: user input in os.Open
func handler(w http.ResponseWriter, r *http.Request) {
    filePath := r.FormValue("path")
    f, _ := os.Open("/data/" + filePath)
    defer f.Close()
}
```

## Remediation

1. **Resolve the canonical path and verify it starts with the expected base directory.**

```go
// SAFE: Go — canonical path check
import (
    "net/http"
    "os"
    "path/filepath"
    "strings"
)

const baseDir = "/var/www/uploads"

func handler(w http.ResponseWriter, r *http.Request) {
    name := r.FormValue("filename")
    // Clean and resolve to absolute path
    abs, err := filepath.Abs(filepath.Join(baseDir, filepath.Clean("/"+name)))
    if err != nil || !strings.HasPrefix(abs, baseDir+string(filepath.Separator)) {
        http.Error(w, "invalid path", http.StatusBadRequest)
        return
    }
    data, err := os.ReadFile(abs)
    if err != nil {
        http.Error(w, "not found", http.StatusNotFound)
        return
    }
    w.Write(data)
}
```

```python
# SAFE: Python — realpath + prefix check
import os

BASE_DIR = '/var/www/uploads'

def safe_read(user_filename: str) -> bytes:
    # Resolve symlinks and normalise
    abs_path = os.path.realpath(os.path.join(BASE_DIR, user_filename))
    if not abs_path.startswith(BASE_DIR + os.sep):
        raise ValueError('Path traversal detected')
    with open(abs_path, 'rb') as f:
        return f.read()
```

```javascript
// SAFE: Node.js — path.resolve + startsWith check
const path = require('path');
const fs   = require('fs');

const BASE = path.resolve('/var/www/uploads');

app.get('/download', (req, res) => {
    const requested = path.resolve(BASE, req.query.filename);
    if (!requested.startsWith(BASE + path.sep)) {
        return res.status(400).send('Invalid path');
    }
    res.sendFile(requested);
});
```

2. **Use an allowlist of permitted filenames or identifiers.** Never use the raw filename from user input as part of the path. Map user-visible IDs to real filenames server-side.

3. **Reject filenames that contain `..`, `/`, or `\` outright.** A simple check on the raw input value before any path construction can stop the attack before it starts.

4. **Store uploaded files using server-generated names.** Use a UUID or content hash as the on-disk filename; never preserve the original filename for storage.

## References

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [CAPEC-126: Path Traversal](https://capec.mitre.org/data/definitions/126.html)
- [MITRE ATT&CK T1083 – File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
