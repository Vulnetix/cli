---
title: "VNX-1044 – File Upload without Size Limit"
description: "Detects file read and upload API calls across Go, Java, Node.js, PHP, and Python that may lack upload size restrictions, enabling denial-of-service via resource exhaustion."
---

## Overview

VNX-1044 is an auto-generated broad-pattern rule that searches for file read and upload operations across Go, Java, Node.js, PHP, and Python source files. The rule targets `os.Open` in Go, `FileInputStream` in Java, `fs.readFile` in Node.js, `move_uploaded_file` in PHP, and `open` in Python. These are associated with [CWE-1044](https://cwe.mitre.org/data/definitions/1044.html) in the rule metadata.

Note: CWE-1044 in MITRE's catalog covers "Architecture with Number of Horizontal Layers Outside of Expected Range." The security concern this rule actually addresses — unbounded file upload or read operations — maps more precisely to [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html) and [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html). The CWE mapping is a known limitation of this auto-generated rule.

All flagged patterns represent standard file I/O APIs; findings must be reviewed in context to determine whether upload size limits are enforced before the file operation is reached.

**Severity:** Medium | **CWE:** [CWE-1044](https://cwe.mitre.org/data/definitions/1044.html) | **OWASP:** [A04:2021 – Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)

## Why This Matters

Applications that accept file uploads without enforcing size limits are vulnerable to denial-of-service attacks where an attacker submits extremely large files to exhaust disk space, memory, or processing time. Even internal tools that only accept uploads from authenticated users can be compromised if a legitimate account is taken over.

Unrestricted reads from user-controlled paths can also enable path traversal attacks where an attacker escapes the intended directory by supplying paths containing `../` sequences.

## What Gets Flagged

The rule scans Go, Java, Node.js, PHP, and Python source files for file access patterns:

```python
# FLAGGED: Python open without size check
def handle_upload(filename):
    with open(filename, 'rb') as f:
        data = f.read()
```

```javascript
// FLAGGED: Node.js fs.readFile on user-provided path
app.post('/upload', (req, res) => {
    fs.readFile(req.body.path, (err, data) => { ... });
});
```

```php
// FLAGGED: PHP move_uploaded_file without size validation
move_uploaded_file($_FILES['file']['tmp_name'], $destination);
```

## Remediation

1. Enforce maximum file size limits at the framework or web server level before the request body is read (e.g., `Content-Length` checking, `client_max_body_size` in Nginx).
2. In PHP, check `$_FILES['file']['size']` against an allowable maximum before calling `move_uploaded_file`.
3. In Node.js, use middleware such as `multer` with `limits: { fileSize: MAX_BYTES }`.
4. In Go, wrap the request body with `http.MaxBytesReader` before reading: `r.Body = http.MaxBytesReader(w, r.Body, maxBytes)`.
5. Validate and sanitise file paths to prevent path traversal — resolve the canonical path and confirm it remains within the intended directory.

## References

- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
