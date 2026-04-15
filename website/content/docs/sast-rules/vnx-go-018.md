---
title: "VNX-GO-018 – Go Arbitrary File Write via User-Controlled Path"
description: "Detects os.WriteFile, os.Create, or ioutil.WriteFile calls whose path argument may be derived from HTTP request input without filepath.Clean validation, enabling path traversal attacks."
---

## Overview

This rule detects calls to `os.WriteFile()`, `os.Create()`, or `ioutil.WriteFile()` where the path argument may be derived from user-controlled HTTP request sources — such as `r.URL`, `r.FormValue()`, `r.PathValue()`, route parameters from `chi`, `gorilla/mux`, `gin`, or `echo` — within a surrounding code window of roughly 20 lines, and where no `filepath.Clean()` or `filepath.Rel()` call is present to sanitise the path. An attacker who can control the file path argument can supply `../` sequences or absolute paths to write files outside the intended directory, potentially overwriting executables, configuration files, or credentials. This maps to CWE-22 (Improper Limitation of a Pathname to a Restricted Directory).

Path traversal in file write operations is significantly more severe than path traversal in read operations. While a read traversal leaks data, a write traversal can achieve remote code execution by overwriting interpreted scripts, web server configuration, or process init files. CAPEC-139 (Relative Path Traversal) and MITRE ATT&CK T1083 (File and Directory Discovery) document the broader family of path manipulation techniques.

**Severity:** High | **CWE:** [CWE-22 – Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)

## Why This Matters

File upload handlers are a recurring source of path traversal vulnerabilities. A common pattern in Go web servers is to take a filename from a multipart form field, construct a path by joining it with an upload directory, and write the file. If the filename is used directly without sanitisation, a value such as `"../../etc/cron.d/backdoor"` will write outside the upload directory. Even without `../` sequences, an absolute path like `/etc/passwd` can overwrite critical system files if the process runs as root or with elevated privileges.

Go's `filepath.Clean()` function resolves `.` and `..` elements and removes redundant separators, but it does not confine the result to a base directory. After cleaning, the path must be checked with `strings.HasPrefix(cleanedPath, baseDir)` or `filepath.Rel()` to confirm it remains within the intended directory. Forgetting the prefix check after calling `filepath.Clean()` is itself a common mistake.

## What Gets Flagged

```go
// FLAGGED: user-supplied filename written directly to disk
func uploadHandler(w http.ResponseWriter, r *http.Request) {
    filename := r.FormValue("filename")
    path := filepath.Join("/var/uploads", filename) // traversal risk
    os.WriteFile(path, data, 0644)
}

// FLAGGED: path built from URL parameter without cleaning
func saveHandler(c *gin.Context) {
    name := c.Param("name")
    os.Create("/data/" + name) // traversal: name = "../../etc/crontab"
}
```

## Remediation

1. **Clean the user-supplied path component and verify it stays within the base directory** before any file operation.

   ```go
   // SAFE: clean and confirm the path stays within the upload directory
   const uploadDir = "/var/uploads"

   func uploadHandler(w http.ResponseWriter, r *http.Request) {
       filename := filepath.Base(r.FormValue("filename")) // remove directory components
       cleanPath := filepath.Join(uploadDir, filename)
       cleanPath = filepath.Clean(cleanPath)

       if !strings.HasPrefix(cleanPath, uploadDir+string(filepath.Separator)) {
           http.Error(w, "invalid filename", http.StatusBadRequest)
           return
       }

       if err := os.WriteFile(cleanPath, data, 0644); err != nil {
           http.Error(w, "write failed", http.StatusInternalServerError)
       }
   }
   ```

2. **Use `filepath.Base()` to strip all directory components** from a user-supplied filename before joining it with the base path. This prevents any traversal sequences.

   ```go
   // SAFE: filepath.Base strips all path components leaving only the filename
   func saveFile(baseDir, userFilename string, data []byte) error {
       safe := filepath.Join(baseDir, filepath.Base(userFilename))
       return os.WriteFile(safe, data, 0600)
   }
   ```

3. **Generate server-side filenames** instead of trusting user input for the filename at all. Store the user-provided name as metadata in a database record.

   ```go
   // SAFE: server-generated filename, user name stored in database only
   func uploadHandler(w http.ResponseWriter, r *http.Request) {
       id := uuid.New().String()
       path := filepath.Join("/var/uploads", id)
       os.WriteFile(path, data, 0600)
       db.Store(id, r.FormValue("filename")) // original name in DB, not on disk
   }
   ```

## References

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [CAPEC-139: Relative Path Traversal](https://capec.mitre.org/data/definitions/139.html)
- [MITRE ATT&CK T1083 – File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
- [Go documentation – filepath.Clean](https://pkg.go.dev/path/filepath#Clean)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [OWASP Go-SCP – File handling](https://owasp.org/www-project-go-secure-coding-practices-guide/)
- [Go security best practices](https://go.dev/security/best-practices)
