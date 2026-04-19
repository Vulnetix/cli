---
title: "VNX-GO-023 – SQL injection via string concatenation"
description: "Detects SQL query construction using string concatenation with user input, which can lead to SQL injection vulnerabilities."
---

## Overview

This rule flags instances where SQL queries are constructed by concatenating strings that may contain user input. This pattern can lead to SQL injection vulnerabilities because attackers can manipulate the input to change the query's meaning and execute arbitrary SQL commands.

This maps to [CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html).

**Severity:** High | **CWE:** [CWE-89 – Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html) | **OWASP ASVS:** [V5.3 – Database Security](https://owasp.org/www-project-application-security-verification-standard/)

## Why This Matters

SQL injection occurs when user input is incorrectly allowed to influence SQL queries. Attackers can inject malicious SQL that can read, modify, or delete data, bypass authentication, or even execute administrative operations on the database server.

This is one of the most critical web application security risks and can lead to complete data breach, data manipulation, or loss of data integrity.

## What Gets Flagged

The rule flags SQL query construction patterns that use string concatenation with quote characters and plus signs, which is a common indicator of SQL injection vulnerabilities:

```go
// FLAGGED: SQL query built with string concatenation
func getUser(db *sql.DB, userID string) error {
    query := "SELECT * FROM users WHERE id = " + userID // User ID concatenated directly
    return db.QueryRow(query).Scan(&user)
}

// FLAGGED: SQL query with multiple concatenated parts
func searchProducts(db *sql.DB, category string) error {
    query := "SELECT * FROM products WHERE category = '" + category + "' AND price < " + maxPrice
    // Both category and maxPrice are user-controlled
    return db.Query(query)
}

// FLAGGED: Using fmt.Sprintf for SQL (similar risk)
func updateUser(db *sql.DB, id string, name string) error {
    query := fmt.Sprintf("UPDATE users SET name = '%s' WHERE id = %s", name, id)
    // Both parameters inserted directly into query
    return db.Exec(query)
}
```

## Remediation

1. **Use parameterized queries (prepared statements):** This is the most effective defense against SQL injection:
   ```go
   // SAFE: Use parameterized queries
   func getUser(db *sql.DB, userID string) error {
       query := "SELECT * FROM users WHERE id = $1"
       return db.QueryRow(query, userID).Scan(&user)
   }
   
   // SAFE: Named parameters with sqlx
   func searchProducts(db *sqlx.DB, category string, maxPrice float64) error {
       query := "SELECT * FROM products WHERE category = :category AND price < :maxPrice"
       _, err := db.NamedQuery(query, map[string]interface{}{
           "category": category,
           "maxPrice": maxPrice,
       })
       return err
   }
   ```

2. **Use query builders:** Libraries like squirrel or gorp help build safe queries:
   ```go
   // SAFE: Using squirrel query builder
   func searchProducts(db *sql.DB, category string) error {
       query := sq.Select("*").From("products").
           Where(sq.Eq{"category": category}).
           Where(sq.Lt{"price": maxPrice})
       // ... execute query
   }
   ```

3. **Use ORMs with built-in protection:** Frameworks like GORM automatically handle parameterization:
   ```go
   // SAFE: Using GORM
   func getUser(db *gorm.DB, userID string) error {
       var user User
       return db.Where("id = ?", userID).First(&user).Error
   }
   ```

4. **Input validation as defense-in-depth:** While not a primary defense, validate input matches expected patterns:
   ```go
   // Additional validation (use with parameterized queries)
   if !isNumeric(userID) {
       return errors.New("invalid user ID")
   }
   // Then use parameterized query
   ```

## References

- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP Application Security Verification Standard v4.0 – V5.3 Database Security](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [Go database/sql package documentation](https://pkg.go.dev/database/sql)
- [Squirrel query builder](https://github.com/Masterminds/squirrel)