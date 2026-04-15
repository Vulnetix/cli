---
title: "VNX-PHP-011 – PHP SQL injection via string concatenation"
description: "Detects user-controlled input from PHP superglobals concatenated directly into SQL queries passed to mysql_query(), mysqli_query(), or pg_query(), enabling SQL injection attacks."
---

## Overview

This rule detects SQL queries constructed by concatenating values from PHP superglobals (`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`) directly into the query string passed to `mysql_query()`, `mysqli_query()`, or `pg_query()`. When user-supplied data is embedded in a SQL string without parameterisation, the database cannot distinguish between SQL syntax and data, allowing attackers to alter query structure.

String concatenation into SQL is the canonical form of SQL injection and remains one of the most prevalent vulnerabilities in PHP codebases. It arises when developers treat SQL as a template string rather than a structured query with typed parameters. Functions like `mysql_real_escape_string()` reduce risk but are error-prone — they must be applied consistently and correctly to every value, and bypass techniques exist for character-set edge cases.

The deprecated `mysql_*` function family (removed in PHP 7.0) does not support prepared statements at all, meaning any codebase still using these functions is both vulnerable and running on an unsupported PHP version.

**Severity:** Critical | **CWE:** [CWE-89 – Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)

## Why This Matters

SQL injection allows an attacker to read any data the database user can access — including tables beyond those the application is intended to query. Depending on database configuration, it can also modify or delete data, execute stored procedures, read OS files via `LOAD DATA INFILE` or `xp_cmdshell`, and in some configurations achieve remote code execution on the database host.

Authentication bypass is a particularly common outcome: a login form that constructs `WHERE username='$u' AND password='$p'` can be bypassed with the classic `' OR '1'='1` injection, granting access as the first user in the table without knowing any password.

PHP applications with long lifespans often accumulate dozens of SQL query construction sites, making systematic review essential. The rule fires on the co-occurrence of a query function and a superglobal on the same line, which is the most direct signal of unsanitised concatenation.

## What Gets Flagged

```php
// FLAGGED: user input concatenated into mysql_query()
$id = $_GET['id'];
$result = mysql_query("SELECT * FROM users WHERE id = " . $id);

// FLAGGED: POST data in mysqli_query()
$username = $_POST['username'];
$res = mysqli_query($conn, "SELECT * FROM accounts WHERE name = '$username'");

// FLAGGED: GET param in pg_query()
$pg = pg_query($db, "SELECT * FROM orders WHERE ref = '" . $_GET['ref'] . "'");
```

## Remediation

1. **Use PDO with prepared statements** — bind all user values as parameters, never concatenate them into the SQL string.

2. **Use MySQLi `bind_param()`** as an alternative to PDO for MySQL-specific code.

3. **For PostgreSQL**, use `pg_query_params()` with a parameter array instead of `pg_query()` with concatenation.

4. **Apply the principle of least privilege** to the database user — the application account should not have `DROP`, `FILE`, or administrative privileges.

```php
// SAFE: PDO prepared statement — SQL and data are always separate
$pdo = new PDO('mysql:host=localhost;dbname=app', $user, $pass, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
]);
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id AND active = 1');
$stmt->execute([':id' => $_GET['id']]);
$rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

// SAFE: MySQLi prepared statement
$stmt = $conn->prepare('SELECT * FROM accounts WHERE name = ?');
$stmt->bind_param('s', $_POST['username']);
$stmt->execute();
```

## References

- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [CAPEC-66: SQL Injection](https://capec.mitre.org/data/definitions/66.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [PHP Manual – PDO Prepared Statements](https://www.php.net/manual/en/pdo.prepared-statements.php)
- [PortSwigger Web Security Academy – SQL Injection](https://portswigger.net/web-security/sql-injection)
