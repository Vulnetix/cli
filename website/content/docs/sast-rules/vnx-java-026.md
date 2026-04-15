---
title: "VNX-JAVA-026 – Java Spring File Serving Without Access Control"
description: "Detects Spring and servlet file-serving handlers that return FileSystemResource or InputStreamResource from user-supplied path parameters without verifying the requesting user is authorised to access that file."
---

## Overview

Spring MVC and plain servlet applications frequently need to serve files — reports, exports, attachments, or user-uploaded documents. A common pattern is to accept a filename or path parameter from the HTTP request, resolve it to a `FileSystemResource` or `InputStreamResource`, and return it in the response body. Without an explicit authorisation check before resolving the path, any authenticated (or even unauthenticated) user can request any file the application has read access to. This is Insecure Direct Object Reference (IDOR) at the filesystem level, covered by CWE-552 (Files or Directories Accessible to External Parties).

This rule flags `new FileSystemResource(...)` and `new InputStreamResource(...)` on the same line as `getParameter`, `@PathVariable`, or `@RequestParam` — patterns that indicate the resource path is derived from user input. The presence of user-controlled input in the resource constructor without an adjacent authorisation check is the finding.

Path traversal is a frequent companion vulnerability: if the user-supplied value is not canonicalised and checked against a permitted base directory, an attacker can supply `../../etc/passwd` or `../../application.properties` to read arbitrary files. This rule targets the access-control gap; a separate path-traversal rule covers the canonicalisation gap.

**Severity:** High | **CWE:** [CWE-552 – Files or Directories Accessible to External Parties](https://cwe.mitre.org/data/definitions/552.html)

## Why This Matters

File download endpoints are high-value targets because they often serve sensitive business data — invoices, medical records, contracts, or source code exports. An IDOR vulnerability on a file endpoint means that simply changing a filename parameter from `report-1001.pdf` to `report-1002.pdf` gives an attacker access to another user's data. If the filenames are predictable (sequential IDs, usernames, dates), the entire dataset can be enumerated with a simple script.

The damage extends beyond user data. If the application server has read access to its own configuration files, source code, or private keys, a path traversal on top of an access-control gap can expose those files. A compromised private key or database credential in `application.properties` gives the attacker lateral movement across the entire infrastructure.

Regulatory frameworks including HIPAA, GDPR, and PCI-DSS impose breach notification requirements when personal data is accessed without authorisation, making IDOR vulnerabilities on file endpoints significant compliance events.

## What Gets Flagged

```java
// FLAGGED: FileSystemResource constructed from PathVariable without auth check
@GetMapping("/download/{filename}")
public ResponseEntity<Resource> download(@PathVariable String filename) {
    Resource resource = new FileSystemResource(uploadDir + filename);
    return ResponseEntity.ok().body(resource);
}

// FLAGGED: InputStreamResource from request parameter
@GetMapping("/file")
public ResponseEntity<InputStreamResource> getFile(
        @RequestParam String path) throws IOException {
    return ResponseEntity.ok(new InputStreamResource(new FileInputStream(path)));
}
```

## Remediation

1. **Verify ownership before serving.** Look up the file record in the database using the file identifier and confirm the `ownerId` matches the authenticated user's ID.

2. **Use opaque identifiers.** Store files under random UUIDs rather than original filenames. The UUID is the only identifier exposed in URLs; the filename mapping lives in the database.

3. **Canonicalise and confine paths.** Resolve the path to its canonical form and verify it starts with the permitted base directory before opening the file.

4. **Apply Spring Security method-level security** (`@PreAuthorize`) to restrict endpoint access.

```java
// SAFE: look up file by UUID, verify ownership, confine to upload directory
@GetMapping("/download/{fileId}")
@PreAuthorize("isAuthenticated()")
public ResponseEntity<Resource> download(
        @PathVariable UUID fileId,
        @AuthenticationPrincipal UserDetails user) throws IOException {

    FileRecord record = fileRepo.findById(fileId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));

    // Authorisation: only the owner may download their file
    if (!record.getOwnerId().equals(user.getUsername())) {
        throw new ResponseStatusException(HttpStatus.FORBIDDEN);
    }

    // Path confinement: prevent traversal
    Path target = uploadRoot.resolve(record.getStoredName()).normalize();
    if (!target.startsWith(uploadRoot)) {
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
    }

    Resource resource = new FileSystemResource(target);
    return ResponseEntity.ok()
        .header(HttpHeaders.CONTENT_DISPOSITION,
                "attachment; filename=\"" + record.getDisplayName() + "\"")
        .body(resource);
}
```

## References

- [CWE-552: Files or Directories Accessible to External Parties](https://cwe.mitre.org/data/definitions/552.html)
- [OWASP IDOR Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [Spring Security Reference – Method Security](https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html)
- [CAPEC-87: Forceful Browsing](https://capec.mitre.org/data/definitions/87.html)
