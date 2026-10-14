---
title: "VNX-PHP-010 – PHP Type Juggling in Comparison"
description: "Detects loose comparisons (==, !=, <>) that decide an authentication or integrity check: a hash result compared with a variable or a 0e literal, user input compared with a non-literal secret value, and strcmp() of user input tested with == 0 or negation. Strict comparisons, hash_equals(), password_verify() and input compared with a constant are not reported."
---

## Overview

This rule flags PHP code where a superglobal value (`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`) is compared using the loose equality operator (`==` or `!=`) rather than the strict equality operator (`===` or `!==`). PHP's loose comparison performs type coercion before comparing values, and the coercion rules produce counterintuitive results that attackers can exploit to bypass authentication, skip access checks, and forge token comparisons. This maps to [CWE-697: Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html).

**Severity:** High | **CWE:** [CWE-697 – Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html)

## Why This Matters

PHP's type juggling is one of the most misunderstood aspects of the language's runtime. The `==` operator converts both operands to a common type before comparing, and the conversion rules create a class of authentication bypasses that look correct to a developer reading the code but behave unexpectedly at runtime.

The most impactful example is the **magic hash vulnerability**. PHP converts strings that look like scientific notation (e.g., `"0e12345"`) to floating-point numbers for comparison. Many MD5 and SHA1 hashes happen to start with `0e` followed entirely by digits — these are called "magic hashes". If a stored password hash starts with `0e`, and an attacker supplies a password whose hash also starts with `0e`, the comparison `md5($input) == $stored_hash` evaluates to `true` because both sides become the float `0.0`. Known magic hash inputs for common hash functions are publicly documented and trivially attempted.

Beyond magic hashes, loose comparison enables:
- `"0" == false` and `"" == false` — empty string and zero compare equal to `false`
- `"1" == true` — non-zero strings compare equal to `true`
- `0 == "any_string_not_starting_with_a_digit"` — in PHP 7, any string that does not start with a digit compares equal to `0`
- Array vs scalar comparisons that produce unexpected results

## What Gets Flagged

The rule matches `.php` files where a loose comparison decides a check an attacker can pass through type juggling:

1. the result of `md5()`, `sha1()`, `hash()`, `hash_hmac()`, `crypt()` or a `*_file()` hash compared with a variable, call or property, or with a `'0e<digits>'` literal;
2. user input (a superglobal element, or a variable assigned directly from one, from `json_decode()`, `php://input` or `$request->input()` within the 30 lines above) compared with a variable, call or property when either side names a secret (password, token, secret, hash, signature, hmac, otp, nonce, csrf, api key, auth, digest, code, pin);
3. `strcmp()`/`strcasecmp()`/`strncmp()` of user input whose result is compared loosely with `0` or negated (an array argument makes it return `NULL`).

```php
// FLAGGED: user input against a stored secret
if ($_POST['password'] == $row['password']) { login($row); }

// FLAGGED: magic hash — two different '0e...' digests compare equal
if (md5($plain) == $stored) { return true; }

// FLAGGED: JSON true equals any non-empty string
$data = json_decode(file_get_contents('php://input'));
if ($data->secret == $secret) { process($data); }

// FLAGGED: strcmp(array, ...) returns NULL, and NULL == 0
if (strcmp($_POST['password'], $adminPassword) == 0) { grant(); }
```

Not flagged: `===`/`!==`, `hash_equals()`, `password_verify()`, user input compared with a constant literal such as `$_POST['step'] == '1'` (a request value is always a string, so a non-numeric literal does not juggle), two user values compared with each other (a password confirmation), and comparisons of names that do not denote a secret.

## Remediation

1. **Use `===` (strict equality) everywhere you compare user input.** Strict equality checks type and value without any coercion. This is the single most important change:

```php
// SAFE: strict comparison prevents type juggling
if ($_GET['token'] === $expected_token) {
    // only matches if type AND value are identical
}
```

2. **Use `hash_equals()` for comparing secrets and tokens.** `hash_equals()` performs a constant-time comparison that prevents timing attacks, and it also uses strict type checking internally:

```php
// SAFE: constant-time, type-safe token comparison
if (hash_equals($expected_token, $_GET['token'] ?? '')) {
    // grant access
}
```

3. **Never use MD5 or SHA1 alone for password storage.** Use `password_hash()` and `password_verify()`, which use bcrypt by default and are immune to both magic hash attacks and timing attacks:

```php
// SAFE: proper password hashing and verification
// At registration:
$hash = password_hash($password, PASSWORD_BCRYPT);

// At login:
if (password_verify($_POST['password'], $stored_hash)) {
    // authenticated
}
```

4. **Cast user input to the expected type before comparison.** When you expect an integer, cast it first so that the comparison operates on integers regardless of operator:

```php
// SAFE: explicit cast before comparison
$page = (int) ($_GET['page'] ?? 1);
if ($page === 1) { /* ... */ }
```

5. **Enable strict types at the top of every PHP file.** `declare(strict_types=1)` enforces strict type checking for function arguments and return values, and it changes `switch` statement comparison behavior to use strict equality for the `case` expressions:

```php
<?php
declare(strict_types=1);

// With strict_types, function signatures are enforced
function check_token(string $provided, string $expected): bool {
    return hash_equals($expected, $provided);
}
```

6. **Review magic hash tables for your hash algorithm.** If you have existing password hashes stored as unsalted MD5 or SHA1 strings in your database, any of them may be magic hashes. Migrate to `password_hash()` by rehashing on next successful login.

## References

- [CWE-697: Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html)
- [CAPEC-153: Input Data Manipulation](https://capec.mitre.org/data/definitions/153.html)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [PHP manual: Comparison Operators](https://www.php.net/manual/en/language.operators.comparison.php)
- [PHP manual: password_hash()](https://www.php.net/manual/en/function.password-hash.php)
- [PHP manual: hash_equals()](https://www.php.net/manual/en/function.hash-equals.php)
- [Magic Hashes — whitehatsec.com](https://www.whitehatsec.com/blog/magic-hashes/)
