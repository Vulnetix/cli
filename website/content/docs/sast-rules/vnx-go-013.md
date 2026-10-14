---
title: "VNX-GO-013 – Go Zip/Tar Slip via Archive Entry Name"
description: "Detect Go code that extracts a zip or tar entry to a path built from the entry's name (or writes its Linkname as a symlink) without checking the result stays inside the destination directory."
---

## Overview

This rule flags Go code that writes a zip or tar entry to a path built from the entry's name without a containment check. A malicious archive with entries containing `../` sequences can write files to arbitrary filesystem locations when extracted, including overwriting executables, configuration files, or cron jobs. This maps to [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html).

**Severity:** High | **CWE:** [CWE-22 – Path Traversal](https://cwe.mitre.org/data/definitions/22.html) | **OWASP ASVS:** [V12.5 – File Download](https://owasp.org/www-project-application-security-verification-standard/)

> **Go idiom note:** Go's `archive/zip` and `archive/tar` packages do NOT sanitise entry names — this is documented behaviour, and the responsibility for path validation lies entirely with the calling code. There is no safe default: the secure pattern (validating with `filepath.Rel` or rejecting `..` components) must be implemented explicitly. This is NOT Go idiomatic by default because the standard library deliberately leaves the policy to the application.

## Why This Matters

Zip Slip was disclosed in 2018 and affected thousands of projects across every major language ecosystem. In Go, the standard `archive/zip` and `archive/tar` packages do not sanitise entry names — the application must validate them. A crafted archive with an entry named `../../../etc/cron.d/backdoor` will extract to that exact path if the extraction code blindly joins the entry name with a destination directory. Arbitrary file write typically leads directly to remote code execution.

OWASP ASVS v4.0 requirement **V12.5.2** requires that only explicitly allowed file types may be uploaded and processed. Requirement **V12.1.2** requires that archives are validated to prevent path traversal. CAPEC-139 (Relative Path Traversal) and MITRE ATT&CK T1083 (File and Directory Discovery) are the primary attack classification references.

`go vet` does not detect this pattern. [staticcheck](https://staticcheck.dev/) does not have a dedicated Zip Slip check. Neither [`gosec`](https://github.com/securego/gosec) nor the Go compiler will warn about the missing validation step.

## What Gets Flagged

The rule reports the line where an archive entry's name enters a destination path that is then written. Entries are a `*zip.File` from `range r.File` (or a `*zip.File` parameter) and a `*tar.Header` from `tr.Next()`; the name is `.Name` (or `.FileHeader.Name`), directly or through a variable assigned from it. The path is built with `filepath.Join`, `path.Join` or string concatenation and passed to `os.Create`, `OpenFile`, `Mkdir`/`MkdirAll`, `WriteFile`, `Symlink`, `Link`, `Rename` or `Chmod`. A tar entry's `Linkname` passed to `os.Symlink`/`os.Link` is reported too.

```go
for _, f := range zr.File {
    path := filepath.Join(dest, f.Name) // FLAGGED
    os.MkdirAll(path, 0o755)
}

for {
    hdr, err := tr.Next()
    // ...
    target := filepath.Join(dst, hdr.Name) // FLAGGED
    os.Symlink(hdr.Linkname, target)       // FLAGGED: link target escapes too
}
```

Not reported when the function checks containment: `strings.HasPrefix` of the result against the destination, `filepath.Rel`, `filepath.IsLocal`, `fs.ValidPath`, a `".."` test, `filepath.Base` of the entry name, a rooted clean (`filepath.Clean("/"+name)`), `securejoin.SecureJoin`, `os.OpenRoot`, or a helper named for the check (sanitize, within, safe join, insecure, traversal, zip slip, sub-path, `checkPath`, `validateDest`, `verifyEntry`, `ensureInside`). A `HasPrefix` against a string literal (`strings.HasPrefix(f.Name, "__MACOSX/")`), `filepath.Clean` of the bare name and `filepath.Base` of the archive's own path are not containment checks, so they do not suppress the finding. A joined path that is only printed, compared or used as a map key, code that builds an archive (`header.Name = ...`) and comments are not reported either.

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
