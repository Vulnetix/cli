---
title: "VNX-PHP-003 – PHP File Inclusion with Variable Path"
description: "Detect PHP include/require statements that use user-controlled or variable paths, enabling Local File Inclusion (LFI) and potentially Remote File Inclusion (RFI) leading to arbitrary code execution."
---

## Overview

This rule flags PHP `include`, `require`, `include_once`, and `require_once` statements where the path argument is derived from user-supplied superglobals (`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`) or from a variable concatenation that could be influenced by external input. Allowing user-controlled values to determine which file PHP loads is a Local File Inclusion (LFI) vulnerability; if the server is misconfigured or the application fetches from URLs, it escalates to Remote File Inclusion (RFI) and full remote code execution. This maps to [CWE-98: Improper Control of Filename for Include/Require Statement](https://cwe.mitre.org/data/definitions/98.html).

**Severity:** Critical | **CWE:** [CWE-98 – Improper Control of Filename for Include/Require Statement](https://cwe.mitre.org/data/definitions/98.html)

## Why This Matters

LFI allows an attacker to read any file readable by the web server process. Against a typical PHP application server, this means `/etc/passwd`, `/proc/self/environ`, application `.env` files containing database credentials and API keys, SSH private keys in `/home` directories, and PHP source files themselves. The escalation path from read-only LFI to full code execution is well-understood: if the attacker can write to any file the server will later include — through a log file, an image upload, a session file under `/tmp` — they can inject PHP code into that file and then trigger its inclusion through the LFI vector. This log poisoning technique reliably converts an LFI into RCE. If `allow_url_include` is enabled in `php.ini`, the attacker can provide a remote URL directly as the include path, achieving RCE in a single step without needing any write access.

## What Gets Flagged

The rule matches `.php` files where an include or require statement takes its argument directly from a superglobal or from a variable concatenated with other data.

```php
// FLAGGED: include path directly from GET parameter
include($_GET['page']);

// FLAGGED: require with POST data
require($_POST['template'] . '.php');

// FLAGGED: variable path built from user input
$section = $_REQUEST['section'];
include('pages/' . $section);

// FLAGGED: include_once with cookie value
include_once($_COOKIE['theme'] . '/style.php');
```

## Remediation

1. **Replace variable includes with a strict allowlist.** Define an explicit map of valid page names to file paths. Never construct a filesystem path from user input directly — compare the input against the map and reject anything not in it.

```php
// SAFE: allowlist map — only these pages can ever be included
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

2. **Use `basename()` to strip directory components before validation.** If you must derive a filename from user input, `basename()` strips any `../` traversal sequences and path separators, limiting the input to a simple filename before it reaches the allowlist check:

```php
// SAFE: basename() strips path traversal attempts, then allowlist check
$allowed = ['header', 'footer', 'sidebar'];
$component = basename($_GET['component'] ?? '');

if (!in_array($component, $allowed, true)) {
    http_response_code(400);
    exit;
}

require __DIR__ . '/components/' . $component . '.php';
```

3. **Use `realpath()` to verify the resolved path stays within the expected directory.** After constructing the path, verify that the canonical path starts with your expected base directory:

```php
// SAFE: realpath() confirms the file is inside the allowed directory
$base = realpath(__DIR__ . '/templates');
$file = realpath($base . '/' . basename($_GET['tpl'] ?? '') . '.php');

if ($file === false || strncmp($file, $base, strlen($base)) !== 0) {
    http_response_code(403);
    exit;
}

require $file;
```

4. **Disable `allow_url_include` and `allow_url_fopen` in `php.ini`** unless your application genuinely requires them. These directives are disabled by default in modern PHP but may be enabled in legacy configurations:

```ini
; php.ini — disable remote file inclusion
allow_url_include = Off
allow_url_fopen   = Off
```

5. **Refactor page routing to a dispatcher pattern.** Rather than including files named by the user, map routes to controller classes or functions. This eliminates file inclusion from the user-facing request path entirely.

## References

- [CWE-98: Improper Control of Filename for Include/Require Statement](https://cwe.mitre.org/data/definitions/98.html)
- [CAPEC-193: PHP Remote File Inclusion](https://capec.mitre.org/data/definitions/193.html)
- [OWASP PHP File Inclusion](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [PHP manual: include](https://www.php.net/manual/en/function.include.php)
- [PHP manual: basename()](https://www.php.net/manual/en/function.basename.php)
- [PHP manual: realpath()](https://www.php.net/manual/en/function.realpath.php)
