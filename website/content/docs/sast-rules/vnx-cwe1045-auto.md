---
title: "VNX-1045 – File Upload without Type Restriction"
description: "Detects file save and upload API calls across Go, Java, Node.js, PHP, and Python that may lack content-type validation, enabling upload of dangerous file types."
---

## Overview

VNX-1045 is an auto-generated broad-pattern rule that searches for file persistence and upload patterns across Go, Java, Node.js, PHP, and Python source files. The rule targets `.save` in Python, `upload` in Node.js, `CreateFile` in Go, `File.createTempFile` in Java, and `move_uploaded_file` in PHP. These are associated with [CWE-1045](https://cwe.mitre.org/data/definitions/1045.html) in the rule metadata.

Applications that accept file uploads without validating file type or content may allow attackers to upload executable code — web shells, scripts, or binaries — that can be subsequently executed or delivered to other users. All flagged locations should be reviewed to confirm that content-type allowlisting and file content inspection are in place.

Because this rule matches common upload-related function names broadly, it has a higher false-positive rate on codebases that perform any kind of file persistence. Manual review of each finding is required.

**Severity:** Medium | **CWE:** [CWE-1045](https://cwe.mitre.org/data/definitions/1045.html) | **OWASP:** [A04:2021 – Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)

## Why This Matters

Unrestricted file upload is one of the most impactful vulnerability classes in web applications. An attacker who can upload a PHP web shell, a Python WSGI script, or a JAR file to a location served by the application gains arbitrary code execution on the server. Even if the uploaded file cannot be directly executed, it may be delivered to other users as a malicious download.

File extension checks and MIME type headers provided by the client are trivially bypassed. Effective type validation requires inspecting the file's actual content (magic bytes) and enforcing a strict allowlist of permitted formats.

## What Gets Flagged

The rule scans Go, Java, Node.js, PHP, and Python source files for file upload and save patterns:

```python
# FLAGGED: Django model save without type check
def handle_upload(request):
    uploaded = request.FILES['document']
    instance.file.save(uploaded.name, uploaded)
```

```javascript
// FLAGGED: Node.js upload handler
app.post('/upload', upload.single('file'), (req, res) => {
    // file saved by multer — type restriction not visible at this line
});
```

```php
// FLAGGED: PHP move_uploaded_file
$ext = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
move_uploaded_file($_FILES['file']['tmp_name'], "uploads/$filename");
```

## Remediation

1. Maintain a strict allowlist of permitted file extensions and reject any upload that does not match.
2. Validate file content using magic byte inspection rather than relying on client-supplied MIME type or file extension alone.
3. Store uploaded files outside the web root, or in a location that is not served by the application server with execute permissions.
4. Rename all uploaded files to a server-generated name to prevent directory traversal and web shell naming tricks.
5. Serve uploaded files through a dedicated endpoint that sets an appropriate `Content-Disposition: attachment` header rather than allowing inline execution.

## References

- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [CAPEC-1: Accessing/Intercepting/Modifying HTTP Cookies](https://capec.mitre.org/data/definitions/1.html)
