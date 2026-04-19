---
title: "VNX-GO-027 – Potential path traversal via file path construction"
description: "Detects file path construction using user input without proper validation, which can lead to path traversal vulnerabilities."
---

## Overview

This rule flags instances where file paths are constructed using user-controlled input without proper validation or sanitization. This pattern can lead to path traversal vulnerabilities (also known as directory traversal) where attackers can access files outside of the intended directory.

This maps to [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html).

**Severity:** High | **CWE:** [CWE-22 – Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html) | **OWASP ASVS:** [V5.3.2 – File Path Traversal Protection](https://owasp.org/www-project-application-security-verification-standard/)

## Why This Matters

Path traversal vulnerabilities occur when user input is used to construct file paths without proper validation, allowing attackers to navigate outside of the intended directory structure. This can lead to:
- Reading sensitive files (like `/etc/passwd`, application source code, or configuration files)
- Writing files to unexpected locations (potentially leading to remote code execution)
- Accessing application source code, configuration, or credentials
- Modifying or deleting critical system files

## What Gets Flagged

The rule flags file path construction patterns that use user input from HTTP requests without proper validation:

```go
// FLAGGED: Path construction with user input without validation
func serveFile(w http.ResponseWriter, r *http.Request) {
    userPath := r.URL.Path[len("/files/"):] // Get path after /files/
    fullPath := filepath.Join("./uploads", userPath) // User input used directly
    http.ServeFile(w, r, fullPath) // Potential path traversal
}

// FLAGGED: Using FormValue in path construction
func downloadHandler(w http.ResponseWriter, r *http.Request) {
    filename := r.FormValue("file")
    path := filepath.Join("./docs", filename) // User input in path
    data, err := os.ReadFile(path) // Could read arbitrary files
    // ...
}

// FLAGGED: Using Header values in path
func getConfig(w http.ResponseWriter, r *http.Request) {
    configName := r.Header.Get("X-Config-Name")
    path := fmt.Sprintf("./configs/%s.json", configName)
    // User input directly in format string
    data, err := os.ReadFile(path)
}

// FLAGGED: Path concatenation with user input
func copyFile(w http.ResponseWriter, r *http.Request) {
    src := r.FormValue("source")
    dst := r.FormValue("destination")
    sourcePath := "./data/" + src // String concatenation
    destPath := "./backup/" + dst
    // Copy file operation
}
```

## Remediation

1. **Validate and sanitize user input:** Ensure user input only contains allowed characters and doesn't contain path traversal sequences:
   ```go
   // SAFE: Validate input for path safety
   func isSafePathComponent(input string) bool {
       // Reject empty input
       if input == "" {
           return false
       }
       
       // Reject path traversal attempts
       if strings.Contains(input, "..") || strings.Contains(input, "/") || 
          strings.Contains(input, "\\") {
           return false
       }
       
       // Optional: Restrict to allowed characters (alphanumeric, hyphen, underscore)
       return regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(input)
   }
   
   // Then in handler:
   func serveFile(w http.ResponseWriter, r *http.Request) {
       userPath := r.URL.Path[len("/files/"):]
       if !isSafePathComponent(userPath) {
           http.Error(w, "Invalid file name", http.StatusBadRequest)
           return
       }
       fullPath := filepath.Join("./uploads", userPath)
       // Additional safety check
       if !strings.HasPrefix(fullPath, "./uploads/") {
           http.Error(w, "Access denied", http.StatusForbidden)
           return
       }
       http.ServeFile(w, r, fullPath)
   }
   ```

2. **Use filepath.Clean and verify the result:** Clean the path and ensure it's still within the intended directory:
   ```go
   // SAFE: Use filepath.Clean and verify containment
   func serveFile(w http.ResponseWriter, r *http.Request) {
       userPath := r.URL.Path[len("/files/"):]
       fullPath := filepath.Join("./uploads", userPath)
       cleaned := filepath.Clean(fullPath)
       
       // Verify the cleaned path is still within the intended directory
       if !strings.HasPrefix(cleaned, "./uploads/") {
           http.Error(w, "Access denied", http.StatusForbidden)
           return
       }
       
       http.ServeFile(w, r, cleaned)
   }
   ```

3. **Use a file whitelist:** For known files, use a map of allowed values:
   ```go
   // SAFE: Use whitelist for allowed files
   func serveFile(w http.ResponseWriter, r *http.Request) {
       userPath := r.URL.Path[len("/files/"):]
       allowed := map[string]bool{
           "document1.pdf": true,
           "image.jpg": true,
           "data.csv": true,
       }
       
       if !allowed[userPath] {
           http.Error(w, "File not found", http.StatusNotFound)
           return
       }
       
       fullPath := filepath.Join("./uploads", userPath)
       http.ServeFile(w, r, fullPath)
   }
   ```

4. **Use URL path parameters carefully:** When using routers, validate path parameters:
   ```go
   // SAFE: With validation in handler
   func serveFileHandler(w http.ResponseWriter, r *http.Request) {
       vars := mux.Vars(r)
       filename := vars["filename"]
       if !isSafeFilename(filename) {
           http.Error(w, "Invalid filename", http.StatusBadRequest)
           return
       }
       filepath := filepath.Join("./files", filename)
       // ... serve file
   }
   ```

5. **Consider using a virtual file system:** For serving user-uploaded files:
   - Store files with random generated names
   - Keep mapping of original names to stored names in database
   - Serve files by their stored names, not user-provided names

## References

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP Application Security Verification Standard v4.0 – V5.3.2 File Path Traversal Protection](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Path Traversal Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Cheat_Sheet.html)
- [Go filepath package documentation](https://pkg.go.dev/path/filepath)