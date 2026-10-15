---
title: "VNX-JAVA-028 – SQL injection via string concatenation in Java"
description: "Detects JDBC Statement/Connection, Spring JdbcTemplate and Android SQLiteDatabase rawQuery/execSQL calls whose SQL is built from a SQL literal or text block and a non-constant value by concatenation, +=, concat(), String.format, .formatted() or StringBuilder.append, inline or in a variable assigned above the call. Parameterised queries and constant-only SQL are not reported."
---

## Overview

This rule detects JDBC (`execute`, `executeQuery`, `executeUpdate`, `executeLargeUpdate`, `addBatch`, `prepareStatement`, `prepareCall`) and Spring `JdbcTemplate` (`query*`, `update`, `batchUpdate`) calls whose SQL argument contains a SQL string literal joined with a non-constant value through `+`, `+=`, `.concat()`, `String.format("...%s")` or `StringBuilder.append()`, either inline (also across line breaks) or in a variable built within the 40 lines above the call. SQL made only of literals and UPPER_CASE constants, `?` placeholders with bound arguments, and non-SQL `execute()` calls (HTTP clients, executors) are not reported. The rule does not follow values across methods and does not decide whether the joined value is attacker-controlled. When user-supplied data is embedded directly into a SQL query string without parameterization, an attacker can manipulate the query's structure — altering its logic, extracting unauthorized data, modifying records, or executing administrative commands depending on the database user's privileges. This is classified as CWE-89 (Improper Neutralization of Special Elements used in an SQL Command).

SQL injection remains one of the most prevalent and impactful vulnerabilities in web applications. Despite decades of awareness, string-concatenated queries continue to appear in Java codebases due to developer convenience, copied legacy patterns, and dynamic query generation for reporting or search features. Even a single injectable parameter in an otherwise safe codebase can expose the entire database.

**Severity:** High | **CWE:** [CWE-89 – Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html) | **OWASP:** [A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/) | **CAPEC:** [CAPEC-66 – SQL Injection](https://capec.mitre.org/data/definitions/66.html) | **ATT&CK:** [T1059.003](https://attack.mitre.org/techniques/T1059/003/)

## Why This Matters

A successful SQL injection attack can result in complete compromise of the database: full data exfiltration, unauthorized modification or deletion of records, and in some configurations, remote code execution via database-side features such as `xp_cmdshell` (SQL Server) or `LOAD_FILE`/`INTO OUTFILE` (MySQL). Authentication bypass via injection into login queries (`' OR '1'='1`) is a well-documented attack pattern that requires no database knowledge from the attacker.

In regulated environments (PCI-DSS, HIPAA, GDPR), SQL injection leading to data exposure carries mandatory breach notification requirements and significant fines. Attackers actively scan for SQL injection using automated tools; vulnerable endpoints are typically discovered and exploited within hours of exposure.

## What Gets Flagged

```java
// FLAGGED: string concatenation in executeQuery
String query = "SELECT * FROM users WHERE username = '" + username + "'";
ResultSet rs = stmt.executeQuery(query);

// FLAGGED: String.format used to construct SQL
String sql = String.format("DELETE FROM sessions WHERE user_id = %s", userId);
stmt.executeUpdate(sql);

// FLAGGED: concatenation inside the call
stmt.execute("UPDATE accounts SET balance = " + amount + " WHERE id = " + id);

// FLAGGED: JdbcTemplate and StringBuilder
return jdbcTemplate.queryForList("SELECT * FROM sales WHERE region = '" + region + "'");
StringBuilder sb = new StringBuilder("UPDATE stock SET qty = qty + 1 WHERE sku = '");
sb.append(sku).append("'");
return jdbcTemplate.update(sb.toString());

// NOT FLAGGED: constants only
st.execute("CREATE TABLE IF NOT EXISTS " + TABLE + " (" + COLUMNS + ")");
```

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
