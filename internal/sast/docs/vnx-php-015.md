---
title: "VNX-PHP-015 – PHP Unrestricted File Upload via move_uploaded_file"
description: "Detects uploads stored under a client-chosen name with no extension allowlist: move_uploaded_file() whose destination contains $_FILES[...]['name'] or request input (directly or through variables built from it), and UploadedFile move()/storeAs() given getClientOriginalName() or getClientOriginalExtension() (inline or through a variable). An extension check against an allowlist, or a generated name, suppresses the finding; a client MIME-type check does not."
---

## Overview

This rule flags uploads stored under a name or extension the client chose, when no extension allowlist precedes the store. File upload handling is one of the most complex and frequently exploited topics in PHP. The function itself moves a valid uploaded file from the PHP temporary directory to a permanent location — it is not inherently unsafe, but it is the final step in a validation pipeline that must be completed correctly. If any of the five required safeguards are missing, the most common outcome is webshell upload and remote code execution.

A webshell is a PHP script uploaded as a disguised file (e.g., named `shell.php.jpg` or with a `Content-Type: image/jpeg` header) that, when accessed via a web URL in a directory where PHP execution is enabled, executes arbitrary code under the web server's process identity.

**Severity:** High | **CWE:** [CWE-434 – Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html) | **CAPEC:** [CAPEC-1](https://capec.mitre.org/data/definitions/1.html) | **ATT&CK:** [T1190](https://attack.mitre.org/techniques/T1190/)

> **PHP default behavior:** PHP performs no validation on uploaded files beyond checking that the upload completed without error. `$_FILES['file']['type']` is the MIME type claimed by the HTTP client and is entirely attacker-controlled — it is not derived from the file content. PHP does not inspect file content, validate extensions, or restrict upload destinations. All five safeguards listed below are the application's responsibility.

## Why This Matters

Webshell upload is a critical initial access technique used in real-world breaches across every industry. Once in place, a webshell provides persistent, unauthenticated access to the server with the privileges of the web server process (typically `www-data` or `apache`). From there an attacker can read all application source code and credentials, exfiltrate database contents, pivot to internal network services, and establish long-term persistence.

Bypassing naive upload validation is straightforward and well-documented:

- **Double extensions:** `shell.php.jpg` — a simple extension suffix check passes but Apache `mod_mime` may execute both.
- **Content-Type spoofing:** the `Content-Type` header is client-supplied and trivially set to `image/jpeg`.
- **Null-byte injection:** `shell.php%00.jpg` terminated strings in PHP < 5.3.4.
- **Polyglot files:** valid image data precedes embedded PHP code; `finfo` detects an image but the PHP interpreter executes the trailing code if the extension is `.php`.
- **Extension case variation:** `SHELL.PHP`, `shell.pHp` — case-insensitive server configurations accept these.

**OWASP ASVS v4.0 mapping:** V12.2.1 — Verify that user-uploaded files are stored outside the web root or in a cloud storage bucket. V12.2.2 — Verify that user-uploaded files are not served with executable permissions. V12.2.3 — Verify that user-uploaded files cannot be served as HTML or JavaScript.

## What Gets Flagged

The rule matches `move_uploaded_file()` whose destination (the second argument) contains `$_FILES[...]['name']`, a `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE` value, or a variable built from one within the 40 lines above, and Laravel/Symfony `->move()`/`->storeAs()`/`->storePubliclyAs()` given `getClientOriginalName()` or `getClientOriginalExtension()`, inline or through a variable built from either. The call is treated as validated, and not flagged, when the 40 lines above extract the extension (`pathinfo(..., PATHINFO_EXTENSION)`, `strrpos`/`strrchr`/`explode` on `'.'`, `getClientOriginalExtension()`) and compare it with an allowlist, or `preg_match()` the name against an extension pattern.

```php
// FLAGGED: user-supplied filename used as destination — webshell upload risk
$destination = '/var/www/uploads/' . $_FILES['file']['name'];
move_uploaded_file($_FILES['file']['tmp_name'], $destination);

// FLAGGED: the client's MIME type is not validation; the name keeps .php
$target = "uploads/" . basename($_FILES['uploaded']['name']);
if ($_FILES['uploaded']['type'] == "image/jpeg") {
    move_uploaded_file($_FILES['uploaded']['tmp_name'], $target);
}

// FLAGGED: Laravel keeps the original client name
$file->move(public_path('uploads'), $file->getClientOriginalName());

// FLAGGED: a generated name with the client's extension (shell.php stays .php)
$name = time() . '.' . $file->getClientOriginalExtension();
$file->move(public_path('avatars'), $name);

// NOT FLAGGED: extension allowlisted before the move
$ext = strtolower(pathinfo($_FILES['doc']['name'], PATHINFO_EXTENSION));
if (!in_array($ext, ['pdf', 'txt'], true)) { exit; }
move_uploaded_file($_FILES['doc']['tmp_name'], 'docs/' . $_FILES['doc']['name']);

// NOT FLAGGED: the stored name is generated server-side
move_uploaded_file($_FILES['img']['tmp_name'], '/var/uploads/' . bin2hex(random_bytes(16)) . '.png');
```

Whether the destination is outside the web root is not judged.

## Remediation

All five safeguards below are required. Omitting any one of them creates an exploitable gap.

**1. Validate the file extension against a strict allowlist.** Use `pathinfo()` to extract the extension and check it against a hardcoded array. Reject anything not on the list.

**2. Validate the MIME type via magic bytes — not `$_FILES['file']['type']`.** Use PHP's `finfo` extension to inspect the actual file content.

**3. Store uploaded files outside the web root**, or in a directory where PHP execution is disabled via web server configuration.

**4. Randomise the filename.** Generate an unguessable name with `bin2hex(random_bytes(16))` and append only the validated extension. Never use the original filename.

**5. Enforce a file size limit.** Set `upload_max_filesize` and `post_max_size` in `php.ini` and validate `$_FILES['file']['size']` in code.

```php
<?php
// SAFE: all five safeguards applied
declare(strict_types=1);

$allowedExtensions = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
$allowedMimeTypes  = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
$maxFileBytes      = 5 * 1024 * 1024; // 5 MB

$tmpPath      = $_FILES['avatar']['tmp_name'];
$originalName = $_FILES['avatar']['name'];

// 1. Validate file size
if ($_FILES['avatar']['size'] > $maxFileBytes) {
    throw new RuntimeException('File exceeds maximum allowed size');
}

// 2. Validate extension (allowlist, not blocklist)
$ext = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
if (!in_array($ext, $allowedExtensions, true)) {
    throw new RuntimeException('File type not permitted');
}

// 3. Validate MIME type via magic bytes (ignore $_FILES['type'])
$finfo    = new finfo(FILEINFO_MIME_TYPE);
$mimeType = $finfo->file($tmpPath);
if (!in_array($mimeType, $allowedMimeTypes, true)) {
    throw new RuntimeException('File content does not match permitted types');
}

// 4. Randomise filename — outside web root
$safeName   = bin2hex(random_bytes(16)) . '.' . $ext;
$uploadPath = '/var/uploads/avatars/' . $safeName; // /var/uploads is NOT under /var/www

// 5. Move file
if (!move_uploaded_file($tmpPath, $uploadPath)) {
    throw new RuntimeException('Upload failed');
}
```

**Web server configuration to disable PHP execution in an upload directory (Apache):**

```apache
<Directory /var/www/html/uploads>
    php_flag engine off
    Options -ExecCGI
    RemoveHandler .php .php7 .phtml
</Directory>
```

## References

- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- [CAPEC-1: Accessing/Intercepting/Modifying HTTP Communication](https://capec.mitre.org/data/definitions/1.html)
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [OWASP ASVS v4.0 – V12.2 File Upload Requirements](https://owasp.org/www-project-application-security-verification-standard/)
- [PHP manual: move_uploaded_file()](https://www.php.net/manual/en/function.move-uploaded-file.php)
- [PHP manual: finfo_file()](https://www.php.net/manual/en/function.finfo-file.php)
- [MITRE ATT&CK T1190 – Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
