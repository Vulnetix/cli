---
title: "VNX-PHP-007 – PHP extract() on Superglobal"
description: "Detect calls to extract() on PHP superglobals ($_GET, $_POST, $_REQUEST, $_COOKIE, $_SERVER, $_FILES), which import user-controlled data as local variables and can silently overwrite security-critical variables."
---

## Overview

This rule flags calls to PHP's `extract()` function that operate directly on superglobals: `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_SERVER`, and `$_FILES`. The `extract()` function imports each key of an associative array as a variable into the current scope. When an attacker controls the keys — as they do with any superglobal — they can inject variables of any name and value into the function's local scope, silently overwriting variables that were set before the call, including authentication flags, access control decisions, and database connection handles. This maps to [CWE-621: Variable Extraction Error](https://cwe.mitre.org/data/definitions/621.html).

**Severity:** High | **CWE:** [CWE-621 – Variable Extraction Error](https://cwe.mitre.org/data/definitions/621.html)

## Why This Matters

Legacy PHP applications from the `register_globals` era (PHP 4 and early PHP 5) often used `extract($_GET)` or `extract($_POST)` at the top of pages as a convenience shortcut. This practice directly mirrors `register_globals = On` — a setting removed in PHP 5.4 specifically because it enabled exactly this class of attack. If a page does:

```php
$isAdmin = false;
extract($_GET);
if ($isAdmin) { /* grant admin access */ }
```

An attacker simply requests `?isAdmin=1` and gains admin access. The attack works against any boolean flag, string credential, numeric threshold, or object reference that was set before the `extract()` call, regardless of how carefully those initial assignments were made.

The attack is equally effective against variables that influence SQL queries, file paths, or include statements — all of the variable-based vulnerabilities in this rule set can be enabled or worsened by a prior `extract()` call.

## What Gets Flagged

The rule matches lines where `extract()` is called with any PHP superglobal as its argument.

```php
// FLAGGED: extract() on GET data — can overwrite any local variable
extract($_GET);

// FLAGGED: extract() on POST data
extract($_POST);

// FLAGGED: extract() on REQUEST data
extract($_REQUEST);

// FLAGGED: extract() on cookie data
extract($_COOKIE);

// FLAGGED: extract() on server variables
extract($_SERVER);

// FLAGGED: extract() on uploaded file data
extract($_FILES);
```

## Remediation

1. **Replace `extract()` with explicit variable assignments.** Assign only the specific keys you actually need, with validation on each value. This makes the data flow visible and prevents any unexpected variable injection:

```php
// SAFE: explicit assignments — only the keys you intend, with validation
$username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_SPECIAL_CHARS) ?? '';
$page     = (int) ($_GET['page'] ?? 1);
$sort     = in_array($_GET['sort'] ?? '', ['asc', 'desc'], true) ? $_GET['sort'] : 'asc';
```

2. **Use `filter_input()` and `filter_input_array()` for validated access to superglobals.** These functions apply type-casting and sanitization filters at the point of access, making it impossible to accidentally import unvalidated data:

```php
// SAFE: filter_input_array with explicit field definitions and types
$inputs = filter_input_array(INPUT_POST, [
    'email'    => FILTER_VALIDATE_EMAIL,
    'age'      => FILTER_VALIDATE_INT,
    'redirect' => FILTER_SANITIZE_URL,
]);

$email    = $inputs['email']    ?? null;
$age      = $inputs['age']      ?? null;
$redirect = $inputs['redirect'] ?? '/dashboard';
```

3. **If you encounter `extract()` in legacy code you cannot fully refactor immediately**, at minimum change the flag to `EXTR_SKIP` so that existing variables are never overwritten by incoming data, and combine it with a prefix to namespace imported variables:

```php
// LESS BAD: EXTR_PREFIX_ALL prevents overwriting, but explicit assignment is still better
extract($_GET, EXTR_PREFIX_ALL, 'get');
// Variables become $get_username, $get_page, etc. — original variables are untouched
```

4. **Search the entire codebase for `extract(` calls** and review each one. Legacy codebases that used `register_globals` compatibility shims at the top of shared include files may have this pattern in `common.php`, `init.php`, or `config.php` — files that run on every page.

## References

- [CWE-621: Variable Extraction Error](https://cwe.mitre.org/data/definitions/621.html)
- [CAPEC-17: Using Malicious Files](https://capec.mitre.org/data/definitions/17.html)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [PHP manual: extract()](https://www.php.net/manual/en/function.extract.php)
- [PHP manual: filter_input()](https://www.php.net/manual/en/function.filter-input.php)
- [PHP manual: filter_input_array()](https://www.php.net/manual/en/function.filter-input-array.php)
- [PHP RFC: Remove register_globals](https://www.php.net/manual/en/security.globals.php)
