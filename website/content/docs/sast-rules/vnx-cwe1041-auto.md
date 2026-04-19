---
title: "VNX-1041 – SQL Injection via External Input"
description: "Detects SQL execution patterns across Go, Java, Node.js, PHP, and Python that may allow SQL injection when queries are constructed with unsanitised user input."
---

## Overview

VNX-1041 is an auto-generated broad-pattern rule that searches for SQL execution API calls across Go, Java, Node.js, PHP, and Python source files. The rule targets `cursor.execute` in Python, `query` in Node.js and PHP, `Exec` in Go, and `PreparedStatement` in Java. These patterns are associated with [CWE-1041](https://cwe.mitre.org/data/definitions/1041.html) in the rule metadata.

Note: CWE-1041 in MITRE's catalog covers "Use of Redundant Code," which does not match the rule's intent. The vulnerability being detected is SQL injection, primarily mapped to [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html). The CWE mapping is a known limitation of the auto-generated rule set.

The flagged patterns are not inherently unsafe — `PreparedStatement` in Java, for example, is the recommended mitigation for SQL injection. All findings require manual review to determine whether user-supplied data reaches the database call and whether parameterisation is correctly applied.

**Severity:** Medium | **CWE:** [CWE-1041](https://cwe.mitre.org/data/definitions/1041.html) | **OWASP:** [A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/)

## Why This Matters

SQL injection remains one of the most exploited vulnerability classes, enabling attackers to read or modify arbitrary data, bypass authentication, and in some database configurations execute operating system commands. A single unsanitised query parameter concatenated into a SQL statement can expose an entire database.

Even codebases that use ORMs are not immune — raw query escape hatches, custom query builders, and dynamic `ORDER BY` clauses are common blind spots where injection vulnerabilities persist alongside otherwise safe code.

## What Gets Flagged

The rule scans Go, Java, Node.js, PHP, and Python source files for SQL execution patterns:

```python
# FLAGGED: Python cursor.execute with f-string
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
```

```javascript
// FLAGGED: Node.js query with string concatenation
db.query("SELECT * FROM orders WHERE user='" + req.body.user + "'", cb);
```

```go
// FLAGGED: Go Exec with formatted string
db.Exec(fmt.Sprintf("DELETE FROM sessions WHERE token='%s'", token))
```

## Remediation

1. Use parameterised queries or prepared statements for all database interactions — never concatenate user input into SQL strings.
2. In Python, use `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`.
3. In Go, use `db.Exec("DELETE FROM sessions WHERE token = ?", token)`.
4. In Node.js, use the placeholder syntax provided by your database driver (e.g., `db.query("SELECT ? FROM ...", [val])`).
5. Use an ORM that enforces parameterisation by default, and audit any use of raw query methods within it.
6. Apply least-privilege database accounts so that an injected query cannot access tables outside the application's scope.

## References

- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Query Parameterization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)
- [CAPEC-66: SQL Injection](https://capec.mitre.org/data/definitions/66.html)
