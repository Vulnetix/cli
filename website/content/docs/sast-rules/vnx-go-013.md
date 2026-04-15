---
title: "VNX-GO-013 – Go Zip/Tar Slip via Archive Entry Name"
description: "Detect Go code that joins an archive entry header.Name into a file path via filepath.Join() without validating the result stays within the target directory."
---

## Overview

This rule flags Go code where `filepath.Join` receives an archive entry name (`header.Name`) without path traversal validation. A malicious archive with entries containing `../` sequences can write files to arbitrary filesystem locations when extracted, including overwriting executables, configuration files, or cron jobs. This maps to [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html).

**Severity:** High | **CWE:** [CWE-22 – Path Traversal](https://cwe.mitre.org/data/definitions/22.html)

## Why This Matters

Zip Slip was disclosed in 2018 and affected thousands of projects across every major language ecosystem. In Go, the standard `archive/zip` and `archive/tar` packages do not sanitize entry names — the application must validate them. A crafted archive with an entry named `../../../etc/cron.d/backdoor` will extract to that exact path if the extraction code blindly joins the entry name with a destination directory. Arbitrary file write typically leads directly to remote code execution.

## What Gets Flagged

```go
// FLAGGED: no traversal check on archive entry name
for _, f := range zipReader.File {
    path := filepath.Join(destDir, f.Name) // Zip Slip!
}
```

## Remediation

1. **Validate the resolved path stays within the target directory:**

```go
// SAFE: validate path stays within destination
func safePath(destDir, entryName string) (string, error) {
    destPath := filepath.Clean(filepath.Join(destDir, entryName))
    rel, err := filepath.Rel(destDir, destPath)
    if err != nil || strings.HasPrefix(rel, "..") {
        return "", fmt.Errorf("path traversal detected: %s", entryName)
    }
    return destPath, nil
}
```

2. **Reject entries containing `..` path components:**

```go
if strings.Contains(entry.Name, "..") {
    return fmt.Errorf("illegal entry name: %s", entry.Name)
}
```

3. **Use `github.com/cyphar/filepath-securejoin`** for a battle-tested secure join implementation.

## References

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [Zip Slip Vulnerability (Snyk research)](https://security.snyk.io/research/zip-slip-vulnerability)
- [Go archive/zip package documentation](https://pkg.go.dev/archive/zip)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CAPEC-139: Relative Path Traversal](https://capec.mitre.org/data/definitions/139.html)
