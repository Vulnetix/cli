---
title: "VNX-PHP-018 – PHP sensitive debug output disclosure"
description: "Detects var_dump(), print_r(), or var_export() called with sensitive PHP superglobals ($_SESSION, $_SERVER, $_ENV), exposing session tokens, credentials, and server configuration in the HTTP response."
---

## Overview

This rule detects calls to the PHP debug output functions `var_dump()`, `print_r()`, and `var_export()` when they are passed sensitive superglobals: `$_SESSION`, `$_SERVER`, or `$_ENV`. These superglobals contain information that is operationally necessary during development but critically sensitive in production environments.

`$_SESSION` contains session data including authentication state, user identifiers, CSRF tokens, and any other values the application has stored in the session. `$_SERVER` contains server configuration including the document root, script path, server software version, HTTP headers, and environment-derived values. `$_ENV` contains process environment variables, which in modern deployments frequently include database connection strings, API keys, cloud credentials, and other secrets injected via environment at startup.

Debug output functions are commonly added during development and forgotten when code is merged to production. A single exposed endpoint that dumps `$_ENV` can leak every secret in the deployment environment.

**Severity:** Medium | **CWE:** [CWE-200 – Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

## Why This Matters

Information disclosure is frequently the first step in a multi-stage attack. An attacker who can access a debug endpoint learns the exact server software and PHP version (enabling targeted exploits), the database hostname and credentials (enabling direct database access), API keys for third-party services (enabling lateral movement), the filesystem layout (enabling path traversal exploitation), and session tokens for currently authenticated users (enabling account takeover).

In cloud deployments, `$_ENV` or `$_SERVER` may contain AWS/GCP/Azure credentials, Kubernetes service account tokens, or database passwords. Exposing these in an HTTP response allows an unauthenticated attacker to gain cloud-level access without exploiting any further vulnerability.

Debug output that is conditionally shown only in development can still be dangerous if the condition check relies on an HTTP header or query parameter that an attacker can spoof.

## What Gets Flagged

```php
// FLAGGED: session data dumped to response
var_dump($_SESSION);

// FLAGGED: server environment information exposed
print_r($_SERVER);

// FLAGGED: environment variables (may contain secrets) exported
var_export($_ENV);
```

## Remediation

1. **Remove all `var_dump()`, `print_r()`, and `var_export()` calls** from production code paths. Use version control history to track where they were added.

2. **Use a structured logging library** (Monolog, etc.) to write debug information to log files accessible only to operators, not to the HTTP response.

3. **Never log `$_SESSION`, `$_ENV`, or `$_SERVER` at full verbosity** — log specific values at appropriate log levels with sensitive fields redacted.

4. **Use environment-based feature flags** for debug output, but treat any debug output on a production host as a bug regardless of the flag value.

```php
<?php
// SAFE: log specific values through a logger, not to the response
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

$log = new Logger('app');
$log->pushHandler(new StreamHandler('/var/log/app/debug.log', Logger::DEBUG));

// Log only what you need, redacting sensitive fields
$log->debug('Session state', [
    'user_id'       => $_SESSION['user_id'] ?? null,
    'authenticated' => $_SESSION['authenticated'] ?? false,
    // never log session tokens, CSRF tokens, or raw credential values
]);
```

## References

- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CAPEC-118: Collect and Analyze Information](https://capec.mitre.org/data/definitions/118.html)
- [OWASP Information Exposure Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [PHP Manual – Error Handling and Logging](https://www.php.net/manual/en/book.errorfunc.php)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
