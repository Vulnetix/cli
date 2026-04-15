---
title: "VNX-JAVA-023 – Java Unrestricted File Upload"
description: "Detects MultipartFile upload handlers that store files using the original filename or without validating content type or extension against an allowlist, enabling remote code execution via malicious file upload."
---

## Overview

Unrestricted file upload is one of the most critical vulnerabilities in web applications and is covered by CWE-434. When a Spring MVC `MultipartFile` handler calls `getOriginalFilename()` and passes that name directly to `transferTo()`, `Files.copy()`, `FileOutputStream`, or `Files.write()` without first validating the extension and MIME type, an attacker can upload a `.jsp`, `.jspx`, or other server-executable file. If that file is saved inside the web application's root or a directory served by the application server, a single HTTP request to the uploaded path yields remote code execution.

This rule flags two patterns: lines that both call `getOriginalFilename()` and contain a file-writing operation, and lines that call `getOriginalFilename()` without any adjacent content-type or extension check. The second pattern catches upload handlers that perform validation in a separate method on the same line — these warrant manual review to confirm the validation is actually enforced.

Beyond JSP execution, unrestricted upload enables phishing via stored HTML pages, denial of service via very large files or ZIP bombs, and overwriting of configuration files when path traversal is also possible.

**Severity:** High | **CWE:** [CWE-434 – Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)

## Why This Matters

File upload endpoints are frequently targeted because the reward — remote code execution on the server — is immediate and reliable. Web application firewalls and intrusion detection systems are often ineffective against polyglot files (valid image files that are also valid JSP) or double-extension attacks (`shell.jpg.jsp`). The attacker only needs the server to execute the file once to establish a persistent foothold.

Even when uploaded files are stored outside the webroot, path traversal combined with an unvalidated filename (`../../webapps/ROOT/shell.jsp`) can place the file in an executable location. The `.getOriginalFilename()` value is fully attacker-controlled — it bears no relationship to the actual file content — making it an unsafe input for any filename or extension decision.

High-profile breaches including the 2017 Equifax breach (Apache Struts, file upload vector) and multiple healthcare sector incidents have been traced to unrestricted file upload combined with server-side script execution.

## What Gets Flagged

```java
// FLAGGED: original filename used directly in file write
@PostMapping("/upload")
public String upload(@RequestParam MultipartFile file) throws IOException {
    file.transferTo(new File(uploadDir + file.getOriginalFilename()));
    return "uploaded";
}

// FLAGGED: getOriginalFilename() with no content-type validation visible
String name = file.getOriginalFilename();
Files.copy(file.getInputStream(), targetPath.resolve(name));
```

## Remediation

1. **Validate the extension against an explicit allowlist.** Derive the extension from the server-side content inspection, not from the client-supplied filename.

2. **Check the MIME type using content-based detection** (Apache Tika, `Files.probeContentType()`, or magic-byte inspection) rather than trusting `getContentType()`, which is also client-supplied.

3. **Generate a new, random filename** for storage. Never use the original filename on disk. Store the mapping between the generated name and the display name in a database.

4. **Store uploads outside the webroot** and serve them through a dedicated controller that sets `Content-Disposition: attachment` to prevent in-browser execution.

```java
// SAFE: allowlist validation, content-based MIME check, random stored name
private static final Set<String> ALLOWED_TYPES = Set.of("image/jpeg", "image/png", "application/pdf");

@PostMapping("/upload")
public ResponseEntity<String> upload(@RequestParam MultipartFile file) throws IOException {
    // Content-based MIME detection (not client-supplied Content-Type)
    String detectedMime = new Tika().detect(file.getInputStream());
    if (!ALLOWED_TYPES.contains(detectedMime)) {
        return ResponseEntity.badRequest().body("File type not allowed");
    }

    // Generate a random storage name; never use getOriginalFilename() on disk
    String storedName = UUID.randomUUID() + ".bin";
    Path target = uploadRoot.resolve(storedName);
    Files.copy(file.getInputStream(), target, StandardCopyOption.REPLACE_EXISTING);

    return ResponseEntity.ok(storedName);
}
```

## References

- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [OWASP Java Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Java_Security_Cheat_Sheet.html)
- [Spring Framework: MultipartFile](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/multipart/MultipartFile.html)
- [Apache Tika: Content Detection](https://tika.apache.org/2.9.2/detection.html)
