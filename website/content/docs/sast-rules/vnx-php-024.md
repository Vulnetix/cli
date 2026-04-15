---
title: "VNX-PHP-024 – PHP mb_ereg_replace with variable options enabling eval modifier"
description: "Detects mb_ereg_replace() or mb_eregi_replace() called with a non-literal options parameter or an options string containing the 'e' modifier, which causes PHP to evaluate the replacement string as executable PHP code."
---

## Overview

This rule detects two patterns in calls to `mb_ereg_replace()` and `mb_eregi_replace()`: calls where the options parameter is a variable (rather than a hardcoded string), and calls where the options string contains the `e` modifier. The `e` modifier in PHP's multibyte regex replacement functions triggers evaluation of the replacement string as PHP code via `eval()`. This is equivalent to calling `eval()` directly with the replacement string as input.

The `e` modifier was a historically available but deeply insecure feature that was deprecated in PHP 5.5 for the standard `preg_replace()` function and removed in PHP 7.0. However, it persists in `mb_ereg_replace()` and `mb_eregi_replace()` in certain PHP configurations. When the options parameter contains `e`, the replacement argument — which may be user-controlled — is executed as PHP code after the regex substitution.

Even when the replacement string is not directly user-controlled, passing a variable as the options parameter means the `e` modifier could be introduced by any code path that sets that variable, creating an insecure code pattern that is difficult to audit.

**Severity:** Critical | **CWE:** [CWE-94 – Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)

## Why This Matters

Code injection via `mb_ereg_replace()` with the `e` modifier allows arbitrary PHP code execution in the context of the web server process. Unlike command injection, which requires access to an OS shell, code injection runs inside PHP with direct access to all application state — database connections, session data, file handles, and loaded credentials.

An attacker who can control the replacement string (for example, via a user-supplied template, a database value that feeds into a regex substitution, or a configuration file) can execute any PHP code: read files, write backdoors, query the database, exfiltrate secrets, or escalate to OS command execution via `system()` or `exec()`.

The variable options pattern is dangerous even if the `e` modifier is not currently present, because future code changes or configuration values could introduce it. Static analysis cannot guarantee that a variable options parameter will never contain `e`, making the pattern categorically unsafe.

## What Gets Flagged

```php
// FLAGGED: options parameter is a variable — could contain 'e' modifier
$options = 'i';
$result = mb_ereg_replace($pattern, $replacement, $subject, $options);

// FLAGGED: options string explicitly contains the 'e' eval modifier
$result = mb_ereg_replace('(.+)', $_POST['template'], $subject, 'e');

// FLAGGED: mb_eregi_replace with non-literal options
$result = mb_eregi_replace('\w+', $userTemplate, $text, $opts);
```

## Remediation

1. **Replace `mb_ereg_replace()` with `preg_replace_callback()`**, which provides equivalent regex replacement functionality with a callback function instead of an eval-based mechanism.

2. **Never pass a variable as the options parameter** to `mb_ereg_replace()` — always use a hardcoded string that does not contain `e`.

3. **If `mb_ereg_replace()` must be used**, hardcode the options to a known-safe string like `''`, `'i'`, or `'x'` that does not include `e`.

4. **Audit all uses of `mb_ereg_replace()` and `mb_eregi_replace()`** in the codebase for historical `e` modifier usage.

```php
<?php
// SAFE: use preg_replace_callback() — no eval modifier exists
$result = preg_replace_callback(
    '/(\w+)/',
    function (array $matches): string {
        return strtoupper($matches[1]); // callback, not eval
    },
    $subject
);

// SAFE: mb_ereg_replace with hardcoded safe options (no 'e')
$result = mb_ereg_replace('\s+', ' ', $subject, 'i');
//                                                 ^^ literal, no 'e'
```

## References

- [CWE-94: Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)
- [CAPEC-242: Code Injection](https://capec.mitre.org/data/definitions/242.html)
- [OWASP Code Injection](https://owasp.org/www-community/attacks/Code_Injection)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [PHP Manual – mb_ereg_replace()](https://www.php.net/manual/en/function.mb-ereg-replace.php)
- [PHP RFC – Remove deprecated functionality in PHP 7 (preg_replace /e)](https://wiki.php.net/rfc/remove_deprecated_functionality_in_php7)
