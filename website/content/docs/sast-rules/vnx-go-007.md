---
title: "VNX-GO-007 – Go Path Traversal"
description: "Detect Go code that passes user-controlled input from HTTP requests directly to file system functions without path sanitization, enabling directory traversal attacks."
---

## Overview

This rule detects Go HTTP handlers that pass values from `r.FormValue()` or `r.URL.Query()` directly to file system operations such as `os.Open`, `os.ReadFile`, `filepath.Join`, or `http.ServeFile`. Without sanitization, an attacker can include `../` sequences in the input to escape the intended directory and access or overwrite arbitrary files on the server. This maps to [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html).

**Severity:** High | **CWE:** [CWE-22 – Path Traversal](https://cwe.mitre.org/data/definitions/22.html)

## Why This Matters

Path traversal gives attackers read (and sometimes write) access to files outside the intended directory. Common targets include `/etc/passwd`, `/etc/shadow`, application configuration files containing database credentials, private keys, environment files (`.env`), and application source code. In write-path scenarios, an attacker who can specify the destination path can overwrite binaries, inject malicious content into configuration files, or plant web shells. The attack is simple and requires no special tooling — just URL-encoding `../` sequences or using absolute paths. In containerized deployments where multiple tenants share a pod, path traversal can cross tenant boundaries.

## What Gets Flagged

The rule fires when `os.Open`, `os.ReadFile`, `os.Create`, `filepath.Join`, `http.ServeFile`, or similar file system functions are called with a path argument sourced directly from `r.FormValue()` or `r.URL.Query()`.

```go
// FLAGGED: user input used directly as file path
func downloadHandler(w http.ResponseWriter, r *http.Request) {
    filename := r.FormValue("file")
    data, err := os.ReadFile("/uploads/" + filename)
    // Attacker sends: file=../../etc/passwd
    // Server reads: /uploads/../../etc/passwd => /etc/passwd
    if err == nil {
        w.Write(data)
    }
}
```

```go
// FLAGGED: filepath.Join does not prevent traversal on its own
func serveAsset(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("asset")
    path := filepath.Join("/static", name)
    http.ServeFile(w, r, path)
    // Attacker sends: asset=../../../../etc/ssh/id_rsa
}
```

## Remediation

1. **Canonicalize the path with `filepath.Clean` and verify it stays within the allowed base directory.** After joining the base directory with user input and cleaning the result, check that the cleaned path still begins with the base directory prefix.

```go
import (
    "fmt"
    "net/http"
    "os"
    "path/filepath"
    "strings"
)

const uploadsBase = "/uploads"

func safeFilePath(base, userInput string) (string, error) {
    // Resolve the joined path to its canonical form
    joined := filepath.Join(base, userInput)
    clean := filepath.Clean(joined)

    // Ensure the cleaned path is still within the base directory
    if !strings.HasPrefix(clean, filepath.Clean(base)+string(filepath.Separator)) {
        return "", fmt.Errorf("path traversal detected")
    }
    return clean, nil
}

// SAFE: path validated against base directory before use
func downloadHandler(w http.ResponseWriter, r *http.Request) {
    filename := r.FormValue("file")
    safePath, err := safeFilePath(uploadsBase, filename)
    if err != nil {
        http.Error(w, "invalid file path", http.StatusBadRequest)
        return
    }
    data, err := os.ReadFile(safePath)
    if err != nil {
        http.Error(w, "file not found", http.StatusNotFound)
        return
    }
    w.Write(data)
}
```

2. **Validate the filename against an allowlist pattern.** If filenames follow a predictable format (alphanumeric, limited extension), reject anything that does not match before even constructing the path.

```go
import "regexp"

var safeFilenameRE = regexp.MustCompile(`^[a-zA-Z0-9_-]+\.(pdf|png|jpg)$`)

func validateFilename(name string) bool {
    return safeFilenameRE.MatchString(name)
}
```

3. **Use `http.FileServer` with `http.Dir` for static file serving.** Go's `http.FileServer` with a sandboxed `http.Dir` safely resolves paths and prevents traversal without any manual checking.

```go
// SAFE: http.FileServer restricts access to the specified directory
http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("/app/static"))))
```

4. **Reject path separators in user input.** If the input should be a simple filename with no subdirectory, reject any input containing `/`, `\`, or `..` before processing it.

## References

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [Go path/filepath package documentation](https://pkg.go.dev/path/filepath)
- [Go os package documentation](https://pkg.go.dev/os)
- [Go net/http FileServer documentation](https://pkg.go.dev/net/http#FileServer)
- [CAPEC-126: Path Traversal](https://capec.mitre.org/data/definitions/126.html)
- [MITRE ATT&CK T1083 – File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
