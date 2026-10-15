---
title: "VNX-73 – External Control of File Name or Path"
description: "The path argument of a file-system call (open, send_file, new File, Paths.get, fs.readFile, res.download, include, file_get_contents...) comes from the HTTP request, directly or through a variable assigned from it."
---

## Overview

VNX-73 maps to [CWE-73: External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html). It reports a file operation whose path argument is a request value: on the call line, through a variable assigned from the request in the 20 lines above, through a Spring `@RequestParam`/`@PathVariable` parameter, a Flask route `<name>` parameter, or a name destructured from `req.query`/`req.body`/`req.params`.

**Severity:** High | **CWE:** [CWE-73](https://cwe.mitre.org/data/definitions/73.html) | **Languages:** java, node, php, python

## Why This Matters

When the caller chooses the path, they choose the file: `../../etc/passwd`, an absolute path, another tenant's upload, or for `include`/`require` a PHP file to execute. Reads leak secrets and source, writes and deletes corrupt or destroy data.

## What Gets Flagged

```python
return send_file(request.args.get("path"))

full = os.path.join(BASE, request.args["name"])
with open(full) as fh: ...
```

```java
FileInputStream in = new FileInputStream(request.getParameter("file"));
public byte[] report(@RequestParam("name") String filename) {
    return Files.readAllBytes(Paths.get(BASE_DIR, filename));
```

```javascript
fs.readFile(req.query.file, 'utf8', cb);
const { template } = req.body;
res.send(fs.readFileSync(`views/${template}.html`, 'utf8'));
```

```php
include($_GET['page']);
echo file_get_contents($_GET['file']);
```

Not flagged: `send_from_directory`, `res.sendFile`/`res.download` with a `root` option, values passed through `basename`/`secure_filename`/`FilenameUtils.getName`/`path.basename` or an integer conversion, an allow-list or pattern check of the variable before the call, a canonical-path containment check right after building the `File`, request data written into a fixed file, a record looked up by a request value, log lines, comments and strings. Go is covered by VNX-GO-007 and VNX-GO-018.

## Remediation

1. Map the request to a known file: an id looked up server-side, or an allow-list of names.
2. If a name must come from the request, reduce it to a bare name (`basename`, `secure_filename`), join it to a fixed directory, canonicalise the result and confirm it is still inside that directory.
3. Use the framework's safe helpers: `send_from_directory`, `res.sendFile(name, { root })`.

## References

- [CWE-73: External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
