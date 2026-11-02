---
title: "VNX-1025 – Comparison Using Wrong Factors"
description: "A comparison that examines the wrong property of its operands, so it can succeed or fail regardless of the values the author meant to compare. Reported: in Java, == or != between object references where a value comparison was meant (a String literal operand, a String-returning call such as getParameter/getHeader/trim/toString, a variable declared String a few dozen lines above, or two variables declared Integer/Long/BigDecimal and other boxed types), and classes compared by name (getClass().getName()/getSimpleName() with equals or ==); in Python, `is`/`is not` against a str, bytes, number, list, dict or empty-tuple literal in an if/elif/while/assert/return statement (also the first line of a condition that wraps) or an assignment, and type(x).__name__ or x.__class__.__name__ compared with ==/!=; in JavaScript/TypeScript, ==/=== against a fresh [] or {} literal (always a different object), x.constructor.name compared with ==/===, and typeof compared with a string typeof never returns ('array', 'null', 'date', ...); in Go, err.Error() text compared with ==/!= with a non-empty literal or another error's text instead of errors.Is (directly or through a variable assigned err.Error() a few lines above), and switch err.Error() {, and reflect.TypeOf(x).Name()/String() or fmt.Sprintf(\"%T\") compared with ==; in PHP, loose ==/!= with an md5/sha1/hash/hash_hmac/crypt result, directly or through a variable assigned one a few lines above (\"0e...\" hashes compare as numbers), strcmp/strcasecmp(...) == 0 and !strcmp(...) (NULL == 0 when an argument is an array), and get_class() compared with a string literal. Not reported: err.Error() != \"\" (an emptiness test), comparisons with null/None/True/False, enums, primitives and char literals, equals()/Objects.equals/MessageDigest.isEqual/hash_equals/password_verify/errors.Is/instanceof/isinstance, strict === in PHP, a.intern() == b.intern(), get_class() against ::class or __CLASS__, timing-unsafe comparison of secrets (a different weakness), test code, comments and the pattern inside string literals. Two comparisons are reported by a more precise rule, so the line is reported once: a Java String compared with a string literal by == or != by VNX-597 (String compared with == instead of equals()), and a PHP loose comparison VNX-PHP-010 reports (a hash compared with ==, strcmp() == 0 on request data: PHP type juggling)."
---

## Overview

VNX-1025 reports [CWE-1025: Comparison Using Wrong Factors](https://cwe.mitre.org/data/definitions/1025.html): a comparison that examines the wrong property of its operands, so it can succeed or fail regardless of the values the author meant to compare.

What is reported:

- **Java**: `==` or `!=` between object references where a value comparison was meant. That covers a String literal operand, a String-returning call (`getParameter`, `getHeader`, `trim`, `toString` ...), a variable declared `String` in the enclosing method, and two variables declared `Integer`/`Long`/`BigDecimal` or another boxed type. Classes compared by name (`getClass().getName()`/`getSimpleName()` with `equals` or `==`) are also reported.
- **Python**: `is`/`is not` against a str, bytes, number, list, dict or empty-tuple literal in an `if`/`elif`/`while`/`assert`/`return`, and `type(x).__name__` or `x.__class__.__name__` compared with `==`/`!=`.
- **JavaScript/TypeScript**: `==`/`===` against a fresh `[]` or `{}` (always a different object), `x.constructor.name` compared with `==`/`===`, and `typeof` compared with a string `typeof` never returns (`'array'`, `'null'`, `'date'` ...).
- **Go**: `err.Error()` text compared with `==`/`!=` instead of `errors.Is` (directly, or through a variable assigned `err.Error()` a few lines above), and `reflect.TypeOf(x).Name()`/`String()` or `fmt.Sprintf("%T")` compared with `==`.
- **PHP**: loose `==`/`!=` with an `md5`/`sha1`/`hash`/`hash_hmac`/`crypt` result (`"0e..."` hashes compare as numbers), `strcmp`/`strcasecmp(...) == 0` (`NULL == 0` when an argument is an array), and `get_class()` compared with a string literal.

Not reported: comparisons with `null`/`None`/`True`/`False`, enums, primitives and char literals; `equals()`, `Objects.equals`, `MessageDigest.isEqual`, `hash_equals`, `password_verify`, `errors.Is`, `instanceof` and `isinstance`; strict `===` in PHP; `a.intern() == b.intern()`; `get_class()` against `::class` or `__CLASS__`; timing-unsafe comparison of secrets (a different weakness); test code, comments and the pattern inside string literals.

Two comparisons are reported by a more precise rule, so the same line is not reported twice: a Java String compared with a string literal (`referer != "NULL"`) by [VNX-597](vnx-597), and a PHP loose comparison that decides an authentication or integrity check (`$token == md5(...)`, `strcmp($_POST['password'], $stored) == 0`) by [VNX-PHP-010](vnx-php-010).

**Severity:** Low | **CWE:** [CWE-1025](https://cwe.mitre.org/data/definitions/1025.html)

## Why This Matters

These comparisons look right and pass simple tests, then decide security checks wrongly. In Java, `request.getParameter("role") == "admin"` compares object identity and is false for every request, while two interned constants compare equal by accident. PHP's `md5($token) == $hash` treats `"0e1234..."` hashes as the number zero, so unrelated tokens match. `strcmp($_POST['password'], $stored) == 0` passes when the password is sent as an array. A class or error compared by name is fooled by any class or message that reuses the name.

## What Gets Flagged

```java
return request.getParameter("role") == expectedRole;                        // FLAGGED
if (plugin.getClass().getName().equals("com.acme.plugins.TrustedPlugin")) { // FLAGGED
```

```python
if role is "admin":                                                          # FLAGGED
return type(user).__name__ == "Superuser"                                    # FLAGGED
```

```javascript
if (typeof filter === 'array') {                                             // FLAGGED
if (user.roles === []) {                                                     // FLAGGED
```

```go
if err.Error() == "connection reset by peer" {                               // FLAGGED
```

```php
if (md5($token) == '5d41402abc4b2a76b9719d911017c592') {                     // FLAGGED
if (get_class($handler) == 'AdminHandler') {                                 // FLAGGED
```

## What Is Not Flagged

```java
return "admin".equals(request.getParameter("role"));
```

```php
if (hash_equals($user['reset_hash'], md5($token))) {
// reported by VNX-PHP-010: if (md5($token) == $user['reset_hash']) {
```

## Remediation

1. Java: compare values with `equals()`/`Objects.equals`, and types with `instanceof` or `getClass() == Other.class`.
2. Python: use `==` for values and `isinstance` for types.
3. JavaScript: use `Array.isArray`, `.length`, `instanceof` or `=== null`.
4. Go: use `errors.Is`/`errors.As` and type switches.
5. PHP: use `===`, `hash_equals` and `password_verify`.

## References

- [CWE-1025: Comparison Using Wrong Factors](https://cwe.mitre.org/data/definitions/1025.html)
- [CWE-597: Use of Wrong Operator in String Comparison](https://cwe.mitre.org/data/definitions/597.html)
- [PHP: Comparison operators and type juggling](https://www.php.net/manual/en/language.operators.comparison.php)
