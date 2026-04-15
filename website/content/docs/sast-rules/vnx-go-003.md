---
title: "VNX-GO-003 – SQL Injection via fmt.Sprintf"
description: "Detect Go database queries built with fmt.Sprintf or string concatenation, which allow SQL injection when any part of the query string originates from user input."
---

## Overview

This rule flags Go code where SQL queries are constructed using `fmt.Sprintf` and passed directly to `database/sql` methods (`Query`, `QueryRow`, `Exec`, `QueryContext`, `ExecContext`) or GORM's `Raw`. When user-controlled input is embedded in a SQL string through format verbs or string concatenation, an attacker can alter the query's logic, bypass authentication, read arbitrary data, modify or delete records, and in some database configurations execute operating system commands. This is [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html).

**Severity:** Critical | **CWE:** [CWE-89 – SQL Injection](https://cwe.mitre.org/data/definitions/89.html)

## Why This Matters

SQL injection is consistently ranked in the OWASP Top 10 because its impact is catastrophic and exploitation is straightforward. An attacker who can inject into a login query can authenticate as any user, including administrators, without knowing their password. An injected `UNION SELECT` can dump entire tables — customer records, payment data, credentials — in a single request. Destructive payloads (`DROP TABLE`, mass `DELETE`) can cause irreversible data loss. In databases like PostgreSQL that support `COPY TO/FROM` or stored procedures with filesystem access, SQL injection can escalate to remote code execution on the database host. The `fmt.Sprintf` pattern in Go is especially dangerous because it looks innocuous and is easy to introduce during rapid development.

## What Gets Flagged

The rule matches any `.go` line where a `database/sql` query method or GORM's `Raw` is called with a `fmt.Sprintf`-formatted argument. It covers both the standard library and the common ORM pattern.

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
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [Go database/sql package documentation](https://pkg.go.dev/database/sql)
- [GORM Security documentation](https://gorm.io/docs/security.html)
- [CAPEC-66: SQL Injection](https://capec.mitre.org/data/definitions/66.html)
- [MITRE ATT&CK T1190 – Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
