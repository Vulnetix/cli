---
title: "VNX-GO-013 – Go Zip/Tar Slip via Archive Entry Name"
description: "Detect Go code that joins an archive entry header.Name into a file path via filepath.Join() without validating the result stays within the target directory."
---

## Overview

This rule flags Go code where `filepath.Join` receives an archive entry name (`header.Name`) without path traversal validation. A malicious archive with entries containing `../` sequences can write files to arbitrary filesystem locations when extracted, including overwriting executables, configuration files, or cron jobs. This maps to [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html).

**Severity:** High | **CWE:** [CWE-22 – Path Traversal](https://cwe.mitre.org/data/definitions/22.html) | **OWASP ASVS:** [V12.5 – File Download](https://owasp.org/www-project-application-security-verification-standard/)

> **Go idiom note:** Go's `archive/zip` and `archive/tar` packages do NOT sanitise entry names — this is documented behaviour, and the responsibility for path validation lies entirely with the calling code. There is no safe default: the secure pattern (validating with `filepath.Rel` or rejecting `..` components) must be implemented explicitly. This is NOT Go idiomatic by default because the standard library deliberately leaves the policy to the application.

## Why This Matters

Zip Slip was disclosed in 2018 and affected thousands of projects across every major language ecosystem. In Go, the standard `archive/zip` and `archive/tar` packages do not sanitise entry names — the application must validate them. A crafted archive with an entry named `../../../etc/cron.d/backdoor` will extract to that exact path if the extraction code blindly joins the entry name with a destination directory. Arbitrary file write typically leads directly to remote code execution.

OWASP ASVS v4.0 requirement **V12.5.2** requires that only explicitly allowed file types may be uploaded and processed. Requirement **V12.1.2** requires that archives are validated to prevent path traversal. CAPEC-139 (Relative Path Traversal) and MITRE ATT&CK T1083 (File and Directory Discovery) are the primary attack classification references.

`go vet` does not detect this pattern. [staticcheck](https://staticcheck.dev/) does not have a dedicated Zip Slip check. Neither [`gosec`](https://github.com/securego/gosec) nor the Go compiler will warn about the missing validation step.

## What Gets Flagged

The rule fires when `filepath.Join` appears on the same line as an archive entry name reference (`header.Name` or `Header.Name`).

```go
// FLAGGED: no traversal check on zip entry name
for _, f := range zipReader.File {
    path := filepath.Join(destDir, f.Name) // Zip Slip!
    outFile, _ := os.Create(path)
}

// FLAGGED: tar entry name joined without validation
for {
    header, _ := tarReader.Next()
    path := filepath.Join(destDir, header.Name) // traversal possible
    os.MkdirAll(path, 0755)
}
```

## Remediation

1. **Validate the resolved path stays within the target directory using `filepath.Rel`.** This is the most robust approach and handles both `../` sequences and absolute paths embedded in entry names:

```go
// SAFE: validate path stays within destination
import (
    "fmt"
    "path/filepath"
    "strings"
)

func safePath(destDir, entryName string) (string, error) {
    // Clean joins and resolves all . and .. components
    destPath := filepath.Clean(filepath.Join(destDir, entryName))
    // Rel checks that destPath is actually under destDir
    rel, err := filepath.Rel(destDir, destPath)
    if err != nil || strings.HasPrefix(rel, "..") {
        return "", fmt.Errorf("path traversal detected: %s", entryName)
    }
    return destPath, nil
}

// Usage in zip extraction
for _, f := range zipReader.File {
    outPath, err := safePath(destDir, f.Name)
    if err != nil {
        return err // reject the malicious archive entry
    }
    // ... proceed with extraction to outPath
}
```

2. **Reject entries containing `..` path components** as an additional early guard. This is a simpler check suitable as a first line of defence:

```go
// SAFE: reject entries with path traversal sequences
import "strings"

for _, entry := range zipReader.File {
    if strings.Contains(entry.Name, "..") {
        return fmt.Errorf("illegal archive entry: %s", entry.Name)
    }
    path := filepath.Join(destDir, entry.Name)
    // ... extract safely
}
```

3. **Use `github.com/cyphar/filepath-securejoin`** for a battle-tested secure join implementation. This third-party library provides `securejoin.SecureJoin` which confines all joins to a root directory at the OS level, even against symlink attacks:

```go
// SAFE: SecureJoin prevents all path escape attempts
import securejoin "github.com/cyphar/filepath-securejoin"

for _, f := range zipReader.File {
    outPath, err := securejoin.SecureJoin(destDir, f.Name)
    if err != nil {
        return err
    }
    // outPath is guaranteed to be under destDir
}
```

4. **Cap archive size and entry count** before extracting to prevent zip bomb denial-of-service alongside the path traversal fix:

```go
const maxSize = 100 << 20 // 100 MiB
const maxEntries = 1000

if len(zipReader.File) > maxEntries {
    return fmt.Errorf("archive has too many entries: %d", len(zipReader.File))
}
```

## References

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP Application Security Verification Standard v4.0 – V12 File and Resources](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [OWASP Go Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Go_Security_Cheat_Sheet.html)
- [Zip Slip Vulnerability (Snyk research)](https://security.snyk.io/research/zip-slip-vulnerability)
- [Go archive/zip package documentation](https://pkg.go.dev/archive/zip)
- [Go archive/tar package documentation](https://pkg.go.dev/archive/tar)
- [filepath-securejoin library](https://pkg.go.dev/github.com/cyphar/filepath-securejoin)
- [CAPEC-139: Relative Path Traversal](https://capec.mitre.org/data/definitions/139.html)
- [MITRE ATT&CK T1083 – File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
