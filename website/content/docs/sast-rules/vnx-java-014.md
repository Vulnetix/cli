---
title: "VNX-JAVA-014 – Java Zip Slip via ZipEntry getName()"
description: "Detect Java code that passes ZipEntry.getName() to File or Paths constructors without validating for path traversal sequences, enabling arbitrary file write."
---

## Overview

This rule flags Java code where `ZipEntry.getName()` is passed to `new File()` or `Paths.get()` without verifying the resulting path stays within the intended destination directory. A malicious ZIP archive can contain entries with names like `../../../etc/cron.d/backdoor` that write files outside the target directory when extracted. This maps to [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html).

**Severity:** High | **CWE:** [CWE-22 – Path Traversal](https://cwe.mitre.org/data/definitions/22.html)

## Why This Matters

Java's `ZipEntry.getName()` returns the raw entry name without sanitization. If the name contains `../` sequences and the application joins it with a destination directory, the resolved path can escape the destination. Arbitrary file write typically leads to remote code execution — overwriting JSP files, startup scripts, or configuration is often sufficient.

## What Gets Flagged

```java
// FLAGGED: ZipEntry name used without traversal check
ZipEntry entry = zis.getNextEntry();
File outFile = new File(destDir, entry.getName()); // Zip Slip!
```

## Remediation

1. **Validate the canonical path starts with the destination directory:**

```java
// SAFE: canonical path validation
File outFile = new File(destDir, entry.getName());
String canonicalDest = destDir.getCanonicalPath() + File.separator;
if (!outFile.getCanonicalPath().startsWith(canonicalDest)) {
    throw new SecurityException("Zip Slip detected: " + entry.getName());
}
```

2. **Reject entries containing `..` path components** as a simpler guard.

## References

- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [Zip Slip Vulnerability (Snyk)](https://security.snyk.io/research/zip-slip-vulnerability)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [Java ZipEntry documentation](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/util/zip/ZipEntry.html)
- [CAPEC-139: Relative Path Traversal](https://capec.mitre.org/data/definitions/139.html)
