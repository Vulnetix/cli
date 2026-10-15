---
title: "VNX-41 – Improper Resolution of Path Equivalence"
description: "A directory-containment check (startsWith, startswith, is_relative_to, strings.HasPrefix) is made on a path that was never canonicalised, so an equivalent spelling such as base/../etc/passwd passes it."
---

## Overview

VNX-41 maps to [CWE-41: Improper Resolution of Path Equivalence](https://cwe.mitre.org/data/definitions/41.html). It reports a prefix check against a base directory where the checked path was built (joined, resolved, concatenated) but not canonicalised, inline or through a variable assigned in the 15 lines above.

**Severity:** Medium | **CWE:** [CWE-41](https://cwe.mitre.org/data/definitions/41.html) | **Languages:** go, java, node, python

## Why This Matters

`/srv/files/../../etc/passwd` starts with `/srv/files`, and so does `/srv/files-backup/x`. A containment check on the raw string, or on a `java.nio.file.Path` that has not been normalised, accepts both. The check looks like path-traversal protection and is not.

## What Gets Flagged

```java
if (!f.getAbsolutePath().startsWith(ROOT)) { ... }

Path target = base.resolve(name);
if (!target.startsWith(base)) { ... }
```

```python
full = os.path.join(UPLOAD_DIR, request.args["name"])
if not full.startswith(UPLOAD_DIR): ...

target = BASE / name
if not target.is_relative_to(BASE): ...
```

```javascript
const filePath = PUBLIC_DIR + req.params.name;
if (!filePath.startsWith(PUBLIC_DIR)) { ... }
```

```go
p := rootDir + r.URL.Query().Get("name")
if !strings.HasPrefix(p, rootDir) { ... }
```

Not flagged: paths canonicalised before the check (`getCanonicalPath`, `normalize()`, `toRealPath`, `os.path.realpath`/`abspath`/`normpath`, `Path.resolve()`, `path.resolve`/`normalize`/`join`, `filepath.Join`/`Clean`), a variable reassigned to its canonical form before the check, and prefix checks against a non-directory literal such as `"https://"` or a bare `"/"`.

## Remediation

1. Canonicalise the candidate path and the base: `getCanonicalPath()` or `toRealPath()`, `os.path.realpath`, `path.resolve`, `filepath.Clean`/`EvalSymlinks`.
2. Compare against the canonical base followed by a separator, so `/srv/files-backup` does not match `/srv/files`.
3. Prefer an API that serves from a root safely (`send_from_directory`, `res.sendFile(name, { root })`, `http.FileServer`).

## References

- [CWE-41: Improper Resolution of Path Equivalence](https://cwe.mitre.org/data/definitions/41.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
