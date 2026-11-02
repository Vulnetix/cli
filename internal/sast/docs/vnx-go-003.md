---
title: "VNX-GO-003 – SQL Injection via fmt.Sprintf"
description: "Reports database/sql, sqlx, pgx and GORM query calls whose SQL is built with fmt.Sprintf or concatenation so a value lands where a bind parameter belongs (inside quotes, after a comparison, IN/VALUES/LIMIT), or that embed a request value anywhere. Parameterised queries, %d, server-chosen identifiers, placeholder lists and quoted identifiers are not reported."
---

## Overview

This rule flags Go code where SQL queries are constructed using `fmt.Sprintf` and passed directly to `database/sql` methods (`Query`, `QueryRow`, `Exec`, `QueryContext`, `ExecContext`) or GORM's `Raw`. When user-controlled input is embedded in a SQL string through format verbs or string concatenation, an attacker can alter the query's logic, bypass authentication, read arbitrary data, modify or delete records, and in some database configurations execute operating system commands. This is [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html).

**Severity:** Critical | **CWE:** [CWE-89 – SQL Injection](https://cwe.mitre.org/data/definitions/89.html) | **OWASP ASVS:** [V5.3 – Output Encoding and Injection Prevention](https://owasp.org/www-project-application-security-verification-standard/)

> **Go idiom note:** Parameterized queries ARE the idiomatic Go default for `database/sql`. The `DB.Query`, `DB.QueryRow`, and `DB.Exec` methods all accept variadic arguments that are passed to the driver as parameters — the safe path is the natural API. Using `fmt.Sprintf` to build SQL is an active step away from how the standard library is designed to be used.

## Why This Matters

SQL injection is consistently ranked in the OWASP Top 10 because its impact is catastrophic and exploitation is straightforward. An attacker who can inject into a login query can authenticate as any user, including administrators, without knowing their password. An injected `UNION SELECT` can dump entire tables — customer records, payment data, credentials — in a single request. Destructive payloads (`DROP TABLE`, mass `DELETE`) can cause irreversible data loss. In databases like PostgreSQL that support `COPY TO/FROM` or stored procedures with filesystem access, SQL injection can escalate to remote code execution on the database host. The `fmt.Sprintf` pattern in Go is especially dangerous because it looks innocuous and is easy to introduce during rapid development.

OWASP ASVS v4.0 requirement **V5.3.4** requires that all database queries use parameterized queries or stored procedures to prevent SQL injection. Requirement **V5.3.5** extends this to all dynamic database queries, and **V5.3.6** mandates that ORMs use parameterized queries.

## What Gets Flagged

The rule fires when a `database/sql`, sqlx, pgx or GORM call (`Query`, `QueryRow`, `Exec`, `Prepare` and their `Context` forms, `Raw`, `Queryx`, `MustExec`, `NamedExec`, sqlx `Select`/`Get`, GORM `Where`/`Or`/`Not`/`Having`/`Joins`/`Order`/`Group`) receives SQL built with `fmt.Sprintf` or `+` so that a value lands where a bind parameter belongs: inside quotes, after `=`/`LIKE`, in `IN (...)`, `VALUES (...)` or `LIMIT`/`OFFSET`. A request value is reported in any position, including a table or `ORDER BY` slot. The SQL may be built inline, in a variable a few lines up (multi-line raw strings and `+=` clauses included) or across several lines of the call. Parameterised queries (`$1`, `?`, `@name`), `%d`, server-chosen identifiers, `strings.Repeat("?,", n)` placeholder lists and `pq.QuoteIdentifier` values are not reported.

```go
// FLAGGED: user input interpolated directly into SQL query
func getUser(db *sql.DB, r *http.Request) (*User, error) {
    id := r.FormValue("user_id")
    row := db.QueryRow(fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", id))
    // Attacker sends: user_id=' OR '1'='1
    // Resulting query: SELECT * FROM users WHERE id = '' OR '1'='1'
    // Returns every user in the table
    var u User
    return &u, row.Scan(&u.ID, &u.Name, &u.Email)
}
```

```go
// FLAGGED: GORM Raw query with fmt.Sprintf
func searchProducts(db *gorm.DB, r *http.Request) {
    name := r.FormValue("name")
    var products []Product
    db.Raw(fmt.Sprintf("SELECT * FROM products WHERE name = '%s'", name)).Scan(&products)
}
```

## Remediation

1. **Use parameterized queries with placeholder arguments.** The `database/sql` package supports `$1`, `$2`, ... placeholders (PostgreSQL) or `?` placeholders (MySQL, SQLite). Pass user values as separate arguments — they are never interpolated into the SQL string.

```go
// SAFE: parameterized query; the driver handles escaping
func getUser(db *sql.DB, r *http.Request) (*User, error) {
    id := r.FormValue("user_id")
    row := db.QueryRow("SELECT id, name, email FROM users WHERE id = $1", id)
    var u User
    err := row.Scan(&u.ID, &u.Name, &u.Email)
    return &u, err
}
```

2. **Use parameterized queries with GORM.** GORM's `Where` and `Raw` both accept positional placeholders:

```go
// SAFE: GORM parameterized query
func searchProducts(db *gorm.DB, r *http.Request) {
    name := r.FormValue("name")
    var products []Product
    db.Where("name = ?", name).Find(&products)
    // Or with Raw:
    db.Raw("SELECT * FROM products WHERE name = ?", name).Scan(&products)
}
```

3. **Validate and sanitize inputs before use.** Parameterization is the primary defence, but also validate that input matches the expected format (e.g., integers should parse as integers, UUIDs should match UUID format) and reject unexpected values early.

4. **Apply the principle of least privilege to the database user.** The database account your application connects with should have only the permissions it needs: `SELECT` on read-only queries, `INSERT`/`UPDATE` on write paths — never `DROP`, `CREATE`, or `ALTER` in production.

5. **Never use `fmt.Sprintf` to build any part of a SQL query.** This includes table names, column names, and `ORDER BY` clauses. For dynamic identifiers use a strict allowlist to map user input to hard-coded SQL fragments.

## References

- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP Application Security Verification Standard v4.0 – V5.3 Output Encoding and Injection Prevention](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Go Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Go_Security_Cheat_Sheet.html)
- [Go database/sql package documentation](https://pkg.go.dev/database/sql)
- [GORM Security documentation](https://gorm.io/docs/security.html)
- [CAPEC-66: SQL Injection](https://capec.mitre.org/data/definitions/66.html)
- [MITRE ATT&CK T1190 – Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
