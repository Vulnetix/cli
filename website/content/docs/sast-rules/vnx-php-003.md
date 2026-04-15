---
title: "VNX-PHP-003 – PHP File Inclusion with Variable Path"
description: "Detect PHP include/require statements that use user-controlled or variable paths, enabling Local File Inclusion (LFI) and potentially Remote File Inclusion (RFI) leading to arbitrary code execution."
---

## Overview

This rule flags PHP `include`, `require`, `include_once`, and `require_once` statements where the path argument is derived from user-supplied superglobals (`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`) or from a variable concatenation that could be influenced by external input. Allowing user-controlled values to determine which file PHP loads is a Local File Inclusion (LFI) vulnerability; if the server permits URL wrappers in include paths, it escalates to Remote File Inclusion (RFI) and full remote code execution.

**Severity:** Critical | **CWE:** [CWE-98 – Improper Control of Filename for Include/Require Statement](https://cwe.mitre.org/data/definitions/98.html) | **CAPEC:** [CAPEC-193](https://capec.mitre.org/data/definitions/193.html) | **ATT&CK:** [T1059](https://attack.mitre.org/techniques/T1059/)

> **PHP default behavior:** `allow_url_include` is **Off** by default since PHP 5.2.0, which prevents RFI. However, `allow_url_fopen` is **On** by default, and LFI works regardless of either setting — the attacker only needs the web process to be able to read the targeted file.

## Why This Matters

LFI allows an attacker to include any file readable by the web server process. Against a typical PHP application this means:

- `/etc/passwd` and `/etc/shadow` (if world-readable)
- `/proc/self/environ` (environment variables with secrets)
- Application `.env` files with database credentials and API keys
- PHP source files to extract logic and credentials
- Uploaded files such as images that contain embedded PHP

The escalation path from read-only LFI to full RCE is well-established: if an attacker can write to any file the server will later include — via a log file, an image upload, or a session file under `/tmp/sess_*` — they can inject PHP into that file and then trigger its inclusion through the LFI vector (log poisoning). This reliably converts an LFI into RCE without enabling `allow_url_include`.

If `allow_url_include` is enabled (non-default but common on legacy hosts), the attacker supplies a remote URL directly as the include path for immediate RCE.

**OWASP ASVS v4.0 mapping:** V12.3.1 — Verify that user-submitted filenames are validated against an allowlist of permitted extensions; V5.2.4 — Verify that the application does not use dynamic file inclusion.

## What Gets Flagged

```php
// FLAGGED: include path directly from GET parameter
include($_GET['page']);

// FLAGGED: require with POST data
require($_POST['template'] . '.php');

// FLAGGED: variable path built from user input and concatenated
$section = $_REQUEST['section'];
include('pages/' . $section);

// FLAGGED: include_once with cookie value
include_once($_COOKIE['theme'] . '/style.php');
```

## Remediation

**1. Replace variable includes with a strict allowlist map.**

```php
// SAFE: only these pages can ever be included
$pages = [
    'home'    => __DIR__ . '/pages/home.php',
    'about'   => __DIR__ . '/pages/about.php',
    'contact' => __DIR__ . '/pages/contact.php',
];

$page = $_GET['page'] ?? 'home';

if (!array_key_exists($page, $pages)) {
    http_response_code(404);
    exit('Page not found');
}

require $pages[$page];
```

**2. Use `basename()` to strip directory components before validation.**

```php
// SAFE: basename() strips path traversal, then allowlist check
$allowed = ['header', 'footer', 'sidebar'];
$component = basename($_GET['component'] ?? '');

if (!in_array($component, $allowed, true)) {
    http_response_code(400);
    exit;
}

require __DIR__ . '/components/' . $component . '.php';
```

**3. Use `realpath()` to confirm the resolved path stays within the expected directory.**

```php
// SAFE: realpath() confirms the file is inside the allowed base directory
$base = realpath(__DIR__ . '/templates');
$file = realpath($base . '/' . basename($_GET['tpl'] ?? '') . '.php');

if ($file === false || strncmp($file, $base, strlen($base)) !== 0) {
    http_response_code(403);
    exit;
}

require $file;
```

**4. Disable URL includes and remote file access in `php.ini`** unless genuinely required:

```ini
; php.ini — disable remote file inclusion (RFI prevention)
; allow_url_include is Off by default — confirm it has not been changed
allow_url_include = Off

; allow_url_fopen is On by default — consider disabling if not needed
allow_url_fopen = Off
```

**5. Refactor page routing to a dispatcher pattern.** Map routes to controller classes or functions rather than including files named by the user. Modern frameworks (Laravel, Symfony) do this automatically through their router.

```php
// SAFE: Laravel route dispatch — no dynamic include
Route::get('/page/{slug}', [PageController::class, 'show']);
```

## References

- [CWE-98: Improper Control of Filename for Include/Require Statement](https://cwe.mitre.org/data/definitions/98.html)
- [CAPEC-193: PHP Remote File Inclusion](https://capec.mitre.org/data/definitions/193.html)
- [OWASP Testing Guide – LFI](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [OWASP ASVS v4.0 – V12.3 File Execution](https://owasp.org/www-project-application-security-verification-standard/)
- [PHP manual: include](https://www.php.net/manual/en/function.include.php)
- [PHP manual: allow_url_include](https://www.php.net/manual/en/filesystem.configuration.php#ini.allow-url-include)
- [PHP manual: realpath()](https://www.php.net/manual/en/function.realpath.php)
