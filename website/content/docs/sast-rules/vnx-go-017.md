---
title: "VNX-GO-017 – Go SQL Injection via fmt.Sprintf in Database Call"
description: "Detects database/sql queries constructed with fmt.Sprintf or string concatenation before being passed to db.Exec, db.Query, or related methods, enabling SQL injection when any interpolated value is user-controlled."
---

## Overview

This rule detects Go code where a SQL query string is constructed using `fmt.Sprintf` or string concatenation and then passed to a `database/sql` method such as `db.Exec()`, `db.Query()`, `db.QueryRow()`, or their `Context` variants. If any of the values interpolated into the query string are derived from user input — HTTP request parameters, form values, path segments, or JSON body fields — the code is vulnerable to SQL injection. This maps to CWE-89 (Improper Neutralization of Special Elements Used in an SQL Command).

Go's `database/sql` package provides first-class support for parameterised queries: any driver-compatible placeholder (`?` for MySQL/SQLite, `$1` for PostgreSQL) can be used, and the values are passed as separate arguments to the query method. This prevents SQL injection at the database driver level by ensuring user-supplied values are always treated as data, never as SQL syntax.

The rule fires in two cases: when `fmt.Sprintf` appears directly inside a database method call on the same line, and when `fmt.Sprintf` is used to build a string containing SQL keywords within a few lines of a subsequent database call.

**Severity:** High | **CWE:** [CWE-89 – SQL Injection](https://cwe.mitre.org/data/definitions/89.html)

## Why This Matters

SQL injection remains one of the most exploited vulnerability classes in web applications. CAPEC-66 (SQL Injection) and MITRE ATT&CK T1190 (Exploit Public-Facing Application) both document it as a primary initial access technique. A successful SQL injection attack can allow an attacker to read arbitrary data from the database, modify or delete records, bypass authentication entirely, and in some configurations execute operating system commands.

In Go specifically, the temptation to use `fmt.Sprintf` for query construction is high because Go's string formatting is idiomatic and familiar. Unlike dynamic languages where ORM frameworks often enforce parameterisation, Go developers frequently interact with `database/sql` directly, making it easy to slip into `fmt.Sprintf(query, userValue)` patterns without recognising the risk. The fix — using placeholders and passing values as arguments — requires only a small code change and has zero performance cost.

## What Gets Flagged

```go
// FLAGGED: fmt.Sprintf used directly inside a Query call
rows, err := db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", username))

// FLAGGED: query string built with Sprintf then passed to Exec
query := fmt.Sprintf("DELETE FROM sessions WHERE token = '%s'", r.FormValue("token"))
_, err = db.Exec(query)

// FLAGGED: UPDATE with user-controlled column value
sql := fmt.Sprintf("UPDATE accounts SET role = '%s' WHERE id = %d", role, id)
db.ExecContext(ctx, sql)
```

## Remediation

1. **Use parameterised queries for all database calls.** Replace string interpolation with `?` placeholders (MySQL, SQLite) or `$N` placeholders (PostgreSQL) and pass values as additional arguments.

   ```go
   // SAFE: parameterised query — user input is treated as data, not SQL
   rows, err := db.QueryContext(ctx,
       "SELECT id, email FROM users WHERE name = ?",
       username,
   )
   ```

2. **For dynamic column or table names that cannot be parameterised**, use a strict allowlist and map user input to pre-approved identifiers. Never use raw user input as a table or column name.

   ```go
   // SAFE: allowlist for dynamic column names
   allowed := map[string]string{
       "name":  "name",
       "email": "email",
   }
   col, ok := allowed[r.FormValue("sort")]
   if !ok {
       col = "id"
   }
   rows, err := db.QueryContext(ctx,
       fmt.Sprintf("SELECT * FROM users ORDER BY %s", col), // col from allowlist only
   )
   ```

3. **Consider using a query builder library** such as `squirrel` or an ORM such as `sqlc` or `gorm` that enforces parameterisation by default, reducing the surface area for this class of mistake.

## References

- [CWE-89: Improper Neutralization of Special Elements Used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [CAPEC-66: SQL Injection](https://capec.mitre.org/data/definitions/66.html)
- [MITRE ATT&CK T1190 – Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [Go documentation – database/sql](https://pkg.go.dev/database/sql)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Go-SCP – SQL injection](https://owasp.org/www-project-go-secure-coding-practices-guide/)
- [Go security best practices](https://go.dev/security/best-practices)
