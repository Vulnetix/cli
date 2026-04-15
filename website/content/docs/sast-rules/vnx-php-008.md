---
title: "VNX-PHP-008 – PHP phpinfo() Exposure"
description: "Detect calls to phpinfo() in PHP source files, which disclose detailed server configuration, installed modules, environment variables, and file system paths useful for reconnaissance."
---

## Overview

This rule flags calls to `phpinfo()` anywhere in PHP source files. `phpinfo()` outputs a comprehensive HTML page summarising the PHP runtime environment. While indispensable during local development, any reachable `phpinfo()` output in a production environment hands an attacker a detailed reconnaissance report about your server without requiring any vulnerability to exploit. This maps to [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html).

**Severity:** Medium | **CWE:** [CWE-200 – Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

## Why This Matters

The `phpinfo()` output page reveals an unusually dense set of reconnaissance data in a single request. Specifically, an attacker learns:

- **PHP version and exact build date** — used to identify known CVEs for that specific minor/patch version.
- **Loaded extensions and their versions** — reveals which attack surfaces are active (`gd`, `curl`, `xml`, `soap`, `zip`, `pdo_*`).
- **`php.ini` directives and their current values** — shows whether dangerous settings like `allow_url_include`, `allow_url_fopen`, `disable_functions`, `open_basedir`, and `display_errors` are enabled or disabled.
- **Environment variables** — includes `PATH`, `SERVER_ADDR`, `DOCUMENT_ROOT`, and any variables set in the server environment, which often include secrets injected via deployment pipelines.
- **`$_SERVER` and `$_ENV` contents** — may expose database DSNs, API keys, cloud credentials, or internal hostnames depending on how the application is deployed.
- **Loaded configuration files** — the exact paths to `php.ini` and additional `.ini` files loaded by the runtime.
- **Apache/Nginx module information** — reveals the web server version and configuration.

With this information an attacker can precisely target exploit payloads to the exact versions running on your server, identify which security controls are missing, and find internal hostnames or credentials exposed through environment variables.

## What Gets Flagged

The rule matches any `.php` file containing a call to `phpinfo(` (followed by any arguments or none).

```php
// FLAGGED: standalone phpinfo file often named info.php or phpinfo.php
<?php phpinfo(); ?>

// FLAGGED: phpinfo embedded in a diagnostic route
if ($_GET['debug'] === 'info') {
    phpinfo();
}

// FLAGGED: phpinfo with section flag — still discloses sensitive data
phpinfo(INFO_ENVIRONMENT);
```

## Remediation

1. **Delete any standalone `phpinfo()` files from the codebase and web root.** Files commonly named `info.php`, `phpinfo.php`, `test.php`, or `i.php` should be removed entirely. Check the web root (`public_html`, `htdocs`, `public/`, `www/`) and any directories served as static assets.

2. **Remove `phpinfo()` calls from application code.** Use your IDE's global search for `phpinfo` across the entire project. Remove every occurrence.

```bash
# Find all phpinfo() calls in the project
grep -r "phpinfo" /path/to/project --include="*.php"
```

3. **Use structured environment inspection instead of phpinfo() in legitimate diagnostic tools.** If you need to inspect the PHP configuration programmatically, use `ini_get()`, `phpversion()`, `get_loaded_extensions()`, and `getenv()` to retrieve only the specific values you need, and ensure those endpoints are protected by authentication and only accessible to administrators:

```php
// SAFE: minimal, authenticated diagnostic endpoint
session_start();
if (!isset($_SESSION['admin']) || $_SESSION['admin'] !== true) {
    http_response_code(403);
    exit;
}

header('Content-Type: application/json');
echo json_encode([
    'php_version'       => PHP_VERSION,
    'loaded_extensions' => get_loaded_extensions(),
    'memory_limit'      => ini_get('memory_limit'),
]);
```

4. **Disable `phpinfo()` via `disable_functions` in `php.ini` on production servers.** Even if a call is accidentally reintroduced, the function will be a no-op:

```ini
; php.ini — production configuration
disable_functions = phpinfo,exec,passthru,shell_exec,system,proc_open,popen
```

5. **Set `display_errors = Off` and `expose_php = Off`** in `php.ini` for all production environments. `expose_php = Off` removes the PHP version from HTTP response headers, eliminating another common fingerprinting vector.

## References

- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CAPEC-54: Query System for Information](https://capec.mitre.org/data/definitions/54.html)
- [MITRE ATT&CK T1592 – Gather Victim Host Information](https://attack.mitre.org/techniques/T1592/)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [OWASP Testing for Information Leakage](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server)
- [PHP manual: phpinfo()](https://www.php.net/manual/en/function.phpinfo.php)
- [PHP manual: disable_functions](https://www.php.net/manual/en/ini.core.php#ini.disable-functions)
