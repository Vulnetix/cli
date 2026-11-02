---
title: "VNX-73 – External Control of File Name or Path"
description: "The path argument of a Python or PHP file-system call (open, send_file, os.remove, include, file_get_contents...) comes from the HTTP request, directly or through a variable assigned from it. Java path traversal is reported by VNX-JAVA-009 and Node.js path traversal by VNX-NODE-010."
---

## Overview

VNX-73 maps to [CWE-73: External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html). It reports a Python or PHP file operation whose path argument is a request value: on the call line, through a variable assigned from the request in the 20 lines above, or through a Flask route `<name>` parameter.

Java path traversal (servlet and Spring request values reaching `new File`, `Paths.get`, `Files.*` and friends) is reported by [VNX-JAVA-009](../vnx-java-009/), and Node.js path traversal (`req.query`/`req.params`/`req.body` reaching `fs.*`, `res.sendFile` or `res.download`) by [VNX-NODE-010](../vnx-node-010/). This rule does not read those languages, so one path traversal is reported once.

**Severity:** High | **CWE:** [CWE-73](https://cwe.mitre.org/data/definitions/73.html) | **Languages:** php, python

## Why This Matters

When the caller chooses the path, they choose the file: `../../etc/passwd`, an absolute path, another tenant's upload, or for `include`/`require` a PHP file to execute. Reads leak secrets and source, writes and deletes corrupt or destroy data.

## What Gets Flagged

```python
return send_file(request.args.get("path"))

full = os.path.join(BASE, request.args["name"])
with open(full) as fh: ...
```

```php
include($_GET['page']);
echo file_get_contents($_GET['file']);
```

Not flagged: `send_from_directory`, values passed through `basename`/`secure_filename` or an integer conversion, an allow-list or pattern check of the variable before the call, request data written into a fixed file, a record looked up by a request value, log lines, comments and strings. Java and Node.js files are not read here: their path traversal is reported by VNX-JAVA-009 and VNX-NODE-010. Go is covered by VNX-GO-007 and VNX-GO-018.

## Remediation

1. Map the request to a known file: an id looked up server-side, or an allow-list of names.
2. If a name must come from the request, reduce it to a bare name (`basename`, `secure_filename`), join it to a fixed directory, canonicalise the result and confirm it is still inside that directory.
3. Use the framework's safe helpers, such as Flask's `send_from_directory`.

## References

- [CWE-73: External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
