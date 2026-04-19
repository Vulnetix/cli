---
title: "VNX-GO-026 – Missing file type validation on upload"
description: "Detects file upload handling without apparent file type validation, which can lead to malicious file upload vulnerabilities."
---

## Overview

This rule flags instances where file upload functionality is implemented using Go's standard library multipart form handling but lacks apparent file type validation. Accepting file uploads without validating the file type can lead to malicious file upload vulnerabilities where attackers upload executable code, scripts, or other dangerous files.

This maps to [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html).

**Severity:** High | **CWE:** [CWE-434 – Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html) | **OWASP ASVS:** [V5.2.2 – File Type Verification](https://owasp.org/www-project-application-security-verification-standard/)

## Why This Matters

File upload functionality is a common feature in web applications, but it presents significant security risks if not properly implemented. Without file type validation, attackers can upload:
- Malicious scripts (.php, .py, .sh) that can be executed on the server
- Executable files (.exe, .bin) that can compromise the server
- HTML/JavaScript files that can lead to XSS when served to users
- Files with dangerous extensions that can bypass client-side validation

These vulnerabilities can lead to remote code execution, data theft, server compromise, or use of the server as a malware distribution point.

## What Gets Flagged

The rule flags file upload handling patterns that use Go's multipart form parsing without apparent file type validation:

```go
// FLAGGED: File upload without type validation
func uploadHandler(w http.ResponseWriter, r *http.Request) {
    if err := r.ParseMultipartForm(10 << 20); err != nil {
        http.Error(w, "Unable to parse form", http.StatusBadRequest)
        return
    }
    
    file, handler, err := r.FormFile("upload")
    if err != nil {
        http.Error(w, "Invalid file", http.StatusBadRequest)
        return
    }
    defer file.Close()
    
    // File saved without checking its type
    dst, err := os.Create(filepath.Join("./uploads", handler.Filename))
    if err != nil {
        http.Error(w, "Unable to save file", http.StatusInternalServerError)
        return
    }
    defer dst.Close()
    
    io.Copy(dst, file) // File saved as-is without validation
}

// FLAGGED: Using UploadedFile without validation
func uploadHandler(w http.ResponseWriter, r *http.Request) {
    uploadedFile, handler, err := r.FormFile("upload")
    if err != nil {
        http.Error(w, "Invalid file", http.StatusBadRequest)
        return
    }
    defer uploadedFile.Close()
    
    // No file type checking before processing or saving
    processUploadedFile(uploadedFile, handler.Filename)
}
```

## Remediation

1. **Validate MIME type:** Use Go's `net/http.DetectContentType` or `mime` package to verify the actual file content:
   ```go
   // SAFE: Validate MIME type
   func uploadHandler(w http.ResponseWriter, r *http.Request) {
       if err := r.ParseMultipartForm(10 << 20); err != nil {
           http.Error(w, "Unable to parse form", http.StatusBadRequest)
           return
       }
       
       file, handler, err := r.FormFile("upload")
       if err != nil {
           http.Error(w, "Invalid file", http.StatusBadRequest)
           return
       }
       defer file.Close()
       
       // Read first 512 bytes to detect content type
       buffer := make([]byte, 512)
       _, err := file.Read(buffer)
       if err != nil {
           http.Error(w, "Unable to read file", http.StatusInternalServerError)
           return
       }
       // Reset file pointer for later use
       file.Seek(0, io.SeekStart)
       
       contentType := http.DetectContentType(buffer)
       allowedTypes := map[string]bool{
           "image/jpeg": true,
           "image/png":  true,
           "application/pdf": true,
       }
       
       if !allowedTypes[contentType] {
           http.Error(w, "Invalid file type", http.StatusBadRequest)
           return
       }
       
       // Now safe to save the file
       dst, err := os.Create(filepath.Join("./uploads", handler.Filename))
       // ... rest of upload logic
   }
   ```

2. **Validate file extension:** Check that the file extension matches expected types:
   ```go
   // SAFE: Validate file extension
   func isAllowedExtension(filename string) bool {
       ext := strings.ToLower(filepath.Ext(filename))
       allowed := map[string]bool{
           ".jpg": true, ".jpeg": true,
           ".png": true, ".gif": true,
           ".pdf": true, ".txt": true,
       }
       return allowed[ext]
   }
   
   // Then in upload handler:
   if !isAllowedExtension(handler.Filename) {
       http.Error(w, "Invalid file extension", http.StatusBadRequest)
       return
   }
   ```

3. **Combine multiple validation approaches:** Use both MIME type and extension validation:
   ```go
   // SAFE: Defense in depth - check both content and extension
   func validateFile(file multipart.File, filename string) error {
       // Check extension
       ext := strings.ToLower(filepath.Ext(filename))
       if !isAllowedExtension(ext) {
           return fmt.Errorf("invalid file extension: %s", ext)
       }
       
       // Check content type
       buffer := make([]byte, 512)
       if _, err := file.Read(buffer); err != nil {
           return fmt.Errorf("unable to read file: %v", err)
       }
       file.Seek(0, io.SeekStart) // Reset for later use
       
       contentType := http.DetectContentType(buffer)
       if !isAllowedMIMEType(contentType) {
           return fmt.Errorf("invalid file type: %s", contentType)
       }
       
       // Optional: Additional validation like magic bytes for specific types
       return nil
   }
   ```

4. **Implement file quarantine and scanning:** For high-security applications:
   - Save uploaded files to a quarantine area outside web root
   - Scan with antivirus software
   - Validate file content matches expected format (e.g., use image libraries to verify real images)
   - Only move to public location after passing all validations

## References

- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- [OWASP Application Security Verification Standard v4.0 – V5.2.2 File Type Verification](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [Go net/http package documentation](https://pkg.go.dev/net/http)
- [Go mime package documentation](https://pkg.go.dev/mime)