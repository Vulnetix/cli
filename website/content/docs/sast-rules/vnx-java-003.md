---
title: "VNX-JAVA-003 – SQL Injection via String Concatenation"
description: "Detects JDBC and JPA queries built by concatenating user-controlled input into a SQL string instead of using PreparedStatement with parameterized placeholders."
---

## Overview

This rule detects Java database access code — using raw JDBC (`Statement.executeQuery`, `Statement.executeUpdate`, `createStatement()`), Spring `JdbcTemplate`, or JPA `EntityManager` — where a SQL query string is assembled by concatenating user-supplied values with the `+` operator rather than using parameterized placeholders. This is SQL injection (CWE-89), the most exploited web vulnerability class for over two decades.

**Severity:** Critical | **CWE:** [CWE-89 – Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)

## Why This Matters

SQL injection gives an attacker direct access to the database. Depending on the database user's privileges and the database engine, the attacker can bypass authentication by supplying `' OR '1'='1`, dump every row from every table, modify or delete data, call stored procedures that read local files (`LOAD_FILE`, `OPENROWSET`), or in some configurations execute OS commands (`xp_cmdshell` in SQL Server, `COPY TO/FROM PROGRAM` in PostgreSQL).

Automated exploitation tools such as SQLMap can fully compromise a vulnerable application in minutes once an injectable parameter is identified. The consequences span data breaches, regulatory fines under GDPR/HIPAA/PCI DSS, and complete application compromise.

## What Gets Flagged

The rule matches `.java` files containing `createStatement()`, `executeQuery("`, or `executeUpdate("` — all of which imply a literal SQL string or a string assembled at runtime — as well as `JdbcTemplate` or `EntityManager` query calls where the first argument ends with a `+` concatenation.

```java
// FLAGGED: user input concatenated into a raw Statement
String username = request.getParameter("username");
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE name='" + username + "'");

// FLAGGED: JdbcTemplate with concatenated WHERE clause
String role = request.getParameter("role");
jdbcTemplate.query("SELECT * FROM accounts WHERE role='" + role + "'", rowMapper);

// FLAGGED: JPA EntityManager with concatenated filter
String id = request.getParameter("id");
entityManager.execute("DELETE FROM sessions WHERE token='" + id + "'");
```

## Remediation

1. **Use `PreparedStatement` with `?` placeholders for all JDBC code.** The JDBC driver serializes parameter values correctly, escaping any SQL metacharacters. The query structure is fixed at compile time and cannot be changed by user input.

   ```java
   // SAFE: PreparedStatement with positional parameters
   String username = request.getParameter("username");
   String sql = "SELECT id, email FROM users WHERE name = ?";
   try (PreparedStatement ps = conn.prepareStatement(sql)) {
       ps.setString(1, username);
       try (ResultSet rs = ps.executeQuery()) {
           while (rs.next()) {
               // process row
           }
       }
   }
   ```

2. **Use named parameters with Spring `NamedParameterJdbcTemplate`.** This is the Spring-idiomatic replacement for `JdbcTemplate` when queries have multiple parameters, as it avoids positional confusion.

   ```java
   // SAFE: named parameters with NamedParameterJdbcTemplate
   String sql = "SELECT * FROM accounts WHERE role = :role AND active = :active";
   MapSqlParameterSource params = new MapSqlParameterSource()
       .addValue("role", request.getParameter("role"))
       .addValue("active", true);
   List<Account> accounts = namedJdbcTemplate.query(sql, params, accountRowMapper);
   ```

3. **Use JPA Criteria API or JPQL named parameters.** Never concatenate values into a JPQL string; use `setParameter` instead.

   ```java
   // SAFE: JPQL with named parameter
   TypedQuery<User> query = entityManager.createQuery(
       "SELECT u FROM User u WHERE u.email = :email", User.class);
   query.setParameter("email", request.getParameter("email"));
   List<User> users = query.getResultList();
   ```

4. **Use Spring Data JPA repositories.** Repository methods derived from method names (`findByEmailAndActive`) or annotated with `@Query` and `:param` syntax are parameterized by default.

5. **Apply least-privilege database accounts.** The database user used by the application should not have `DROP`, `CREATE`, or `FILE` privileges. Separate read-only and read-write users where possible.

6. **Add input validation as defence-in-depth.** Validate the type, length, and format of all inputs before they reach the data layer. This does not replace parameterized queries but limits the blast radius of any future injection surface.

## References

- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [CAPEC-66: SQL Injection](https://capec.mitre.org/data/definitions/66.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Java Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Java_Security_Cheat_Sheet.html)
- [Spring JDBC – NamedParameterJdbcTemplate](https://docs.spring.io/spring-framework/docs/current/reference/html/data-access.html#jdbc-NamedParameterJdbcTemplate)
- [OWASP ASVS V5 – Validation, Sanitization and Encoding](https://owasp.org/www-project-application-security-verification-standard/)
- [MITRE ATT&CK T1190 – Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
