---
title: "VNX-JAVA-028 – SQL injection via StringBuilder-assembled SQL in Java"
description: "Detects JDBC Statement/Connection, Spring JdbcTemplate and Android SQLiteDatabase calls whose SQL is assembled in a StringBuilder or StringBuffer with an append() of a non-constant value. SQL concatenated or formatted into a String is reported by VNX-JAVA-003."
---

## Overview

This rule detects JDBC (`execute`, `executeQuery`, `executeUpdate`, `executeLargeUpdate`, `addBatch`, `prepareStatement`, `prepareCall`) and Spring `JdbcTemplate` (`query*`, `update`, `batchUpdate`) calls whose SQL is assembled in a `StringBuilder` or `StringBuffer`, where an `append()` adds a non-constant value: `sb.append(name)`, `sb.append(" AND x = '" + name + "'")`, or a chained `new StringBuilder("SELECT ...").append(id).toString()` written inside the call. The builder is read from its nearest plain assignment within the 40 lines above the call, and a SQL string literal must appear in what it is built from.

SQL concatenated, `+=`-extended or formatted (`String.format`, `concat()`, `.formatted()`) into a `String`, inline or through a variable, is reported by [VNX-JAVA-003](../vnx-java-003/), so the same line is not reported twice. VNX-JAVA-003 does not follow a builder's `append()` calls, which is the shape this rule covers. Builders that append only literals and UPPER_CASE constants, `?` placeholders with bound arguments, and builders that hold no SQL are not reported. The rule follows values only within the enclosing method and does not decide whether the appended value is attacker-controlled. When user-supplied data is embedded directly into a SQL query string without parameterization, an attacker can manipulate the query's structure — altering its logic, extracting unauthorized data, modifying records, or executing administrative commands depending on the database user's privileges. This is classified as CWE-89 (Improper Neutralization of Special Elements used in an SQL Command).

SQL injection remains one of the most prevalent and impactful vulnerabilities in web applications. Despite decades of awareness, string-concatenated queries continue to appear in Java codebases due to developer convenience, copied legacy patterns, and dynamic query generation for reporting or search features. Even a single injectable parameter in an otherwise safe codebase can expose the entire database.

**Severity:** High | **CWE:** [CWE-89 – Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html) | **OWASP:** [A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/) | **CAPEC:** [CAPEC-66 – SQL Injection](https://capec.mitre.org/data/definitions/66.html) | **ATT&CK:** [T1059.003](https://attack.mitre.org/techniques/T1059/003/)

## Why This Matters

A successful SQL injection attack can result in complete compromise of the database: full data exfiltration, unauthorized modification or deletion of records, and in some configurations, remote code execution via database-side features such as `xp_cmdshell` (SQL Server) or `LOAD_FILE`/`INTO OUTFILE` (MySQL). Authentication bypass via injection into login queries (`' OR '1'='1`) is a well-documented attack pattern that requires no database knowledge from the attacker.

In regulated environments (PCI-DSS, HIPAA, GDPR), SQL injection leading to data exposure carries mandatory breach notification requirements and significant fines. Attackers actively scan for SQL injection using automated tools; vulnerable endpoints are typically discovered and exploited within hours of exposure.

## What Gets Flagged

```java
// FLAGGED: a request value appended to the builder
StringBuilder sb = new StringBuilder("UPDATE stock SET qty = qty + 1 WHERE sku = '");
sb.append(sku).append("'");
return jdbcTemplate.update(sb.toString());

// FLAGGED: a concatenation inside an append()
StringBuilder q = new StringBuilder("SELECT * FROM products WHERE 1=1");
if (category != null) q.append(" AND category = '" + category + "'");
return conn.createStatement().executeQuery(q.toString());

// FLAGGED: a chained builder inside the call
stmt.executeUpdate(new StringBuilder("UPDATE invoices SET closed = 1 WHERE number = ").append(number).toString());

// NOT FLAGGED: only constants appended, values bound
StringBuilder sql = new StringBuilder("SELECT id FROM ");
sql.append(TABLE).append(" WHERE customer = ?");
jdbcTemplate.queryForList(sql.toString(), customer);

// NOT FLAGGED HERE: concatenation or formatting into a String (reported by VNX-JAVA-003)
stmt.executeQuery("SELECT * FROM users WHERE username = '" + username + "'");
```

### Operands the method fixes

Before reporting, the rule reads the enclosing method (at most 120 lines up) and asks what each operand actually holds at the call. An operand that provably holds a constant is not run-time data:

- a literal or constant expression it was last assigned on every path to the call;
- the taken side of an `if`/`else` or a ternary whose condition folds to a constant (integer literals, and `int` locals assigned once from a literal);
- the case a `switch` on a constant selects;
- the element a list index (`add`, `add(i, v)`, `set`, `remove(i)`) or a map key (`put`) actually holds, when that is a literal;
- the result of a method in the same file, including a nested class, whose every `return` is a constant.

```java
// NOT FLAGGED: 50 * 2 > 60, so column is always "region_code"
int pageSize = 50;
if (pageSize * 2 > 60) column = "region_code";
else column = request.getParameter("sort");
StringBuilder sb = new StringBuilder("SELECT id FROM orders ORDER BY ");
sb.append(column);
stmt.executeQuery(sb.toString());
```

Anything the analysis cannot resolve stays reported: a condition on run-time data, a call into another class that is handed a run-time value (a call with constant arguments is read as inert, below), a collection filled in a loop or handed to another method, a helper that returns (a transform of) its parameter.

### Calls that cannot bring data in

A call into code the scan cannot see (another class or module) is treated as **inert**, and its value as a constant, when all of these hold:

- its name is not that of a source (`read*`, `next*`, `getParameter*`, `getHeader*`, `getCookie*`, `getenv`, `getProperty`, `query`, `execute`);
- every argument is a constant: a literal, or a name the method fixes;
- its receiver is a type name, a `new` expression with constant arguments, or a local built from such a call, and that local is only ever called with constant arguments.

```java
// NOT REPORTED: the helper is given literals only
sb.append(Columns.name("total")).append(" FROM orders");

// REPORTED: a run-time argument
sb.append(Columns.name(column));

// REPORTED: the receiver was built from, or fed, a run-time value
quoter.setStyle(region);
sb.append(quoter.quote("eu"));

// REPORTED: a source-like method name
sb.append(Prompts.readLine("region"));
```

Anything that fails one of the tests stays reported, so a helper that hands back its argument is never mistaken for a constant.

## Remediation

1. Replace all string-concatenated SQL with `PreparedStatement` and positional parameters (`?`). The JDBC driver handles quoting and escaping, preventing injection regardless of input content.
2. For dynamic table or column names (which cannot be parameterized), use a strict allowlist of permitted identifiers and validate against it before interpolation.
3. Apply the principle of least privilege to database accounts used by the application — a read-only account cannot be abused to `DROP` tables even if injection is possible.
4. Use an ORM (Hibernate, jOOQ) with parameterized query APIs to eliminate manual SQL construction.

```java
// SAFE: PreparedStatement with parameterized query
String sql = "SELECT * FROM users WHERE username = ?";
try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
    pstmt.setString(1, username);
    ResultSet rs = pstmt.executeQuery();
    while (rs.next()) {
        // process results
    }
}

// SAFE: multiple parameters
String updateSql = "UPDATE accounts SET balance = ? WHERE id = ?";
try (PreparedStatement pstmt = conn.prepareStatement(updateSql)) {
    pstmt.setBigDecimal(1, newBalance);
    pstmt.setLong(2, accountId);
    pstmt.executeUpdate();
}
```

## References

- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CAPEC-66: SQL Injection](https://capec.mitre.org/data/definitions/66.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Query Parameterization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)
- [Java SE Documentation — PreparedStatement](https://docs.oracle.com/en/java/javase/17/docs/api/java.sql/java/sql/PreparedStatement.html)
- [PortSwigger Web Security Academy — SQL Injection](https://portswigger.net/web-security/sql-injection)
