---
title: "VNX-JAVA-003 – SQL Injection via String Concatenation"
description: "Reports JDBC, JdbcTemplate, Hibernate native and Android SQLite queries whose SQL text is concatenated or formatted from run-time values instead of bound through ? placeholders."
---

## Overview

This rule detects Java database access code — using raw JDBC (`Statement.executeQuery`, `Statement.executeUpdate`, `createStatement()`), Spring `JdbcTemplate`, or JPA `EntityManager` — where a SQL query string is assembled by concatenating user-supplied values with the `+` operator rather than using parameterized placeholders. This is SQL injection (CWE-89), the most exploited web vulnerability class for over two decades.

**Severity:** Critical | **CWE:** [CWE-89 – Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)

## Why This Matters

SQL injection gives an attacker direct access to the database. Depending on the database user's privileges and the database engine, the attacker can bypass authentication by supplying `' OR '1'='1`, dump every row from every table, modify or delete data, call stored procedures that read local files (`LOAD_FILE`, `OPENROWSET`), or in some configurations execute OS commands (`xp_cmdshell` in SQL Server, `COPY TO/FROM PROGRAM` in PostgreSQL).

Automated exploitation tools such as SQLMap can fully compromise a vulnerable application in minutes once an injectable parameter is identified. The consequences span data breaches, regulatory fines under GDPR/HIPAA/PCI DSS, and complete application compromise.

## What Gets Flagged

The rule reports the SQL argument of JDBC (`executeQuery`, `executeUpdate`, `execute`, `addBatch`, `prepareStatement`, `prepareCall`), Spring `JdbcTemplate` (`query*`, `update`, `batchUpdate`, `execute`), Hibernate `createSQLQuery` and Android `rawQuery`/`execSQL` calls when it is concatenated or formatted with a non-constant value, reads a request value, or is a variable assigned that way within the 40 lines above (multi-line assignments and `sql += ...` included).

```java
// FLAGGED: user input concatenated into a raw Statement
ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");

// FLAGGED: query assembled over several lines, executed below
String query =
    "SELECT * FROM employees WHERE last_name = '"
        + lastName
        + "'";
ResultSet results = statement.executeQuery(query);

// FLAGGED: Android SQLite
db.execSQL("DELETE FROM notes WHERE _id = " + id);

// FLAGGED: DDL, and a statement held in a short local
jdbcTemplate.execute("CREATE SCHEMA \"" + tenant.getSlug() + "\" AUTHORIZATION dba");
st.execute(String.format("DROP SCHEMA %s CASCADE", slug));
```

Not flagged: `?` placeholders with bound values, constant queries or concatenation of literals and `UPPER_CASE` constants, a variable extended with literals only (`sql = sql + " ORDER BY name"`, `sql += " AND active = 1"`), a query that arrives as a plain method parameter, `execute()` on HTTP clients and executors, comments and string literals. JPQL/HQL `createQuery` is covered by VNX-JAVA-015. SQL assembled with `StringBuilder.append()` is reported by [VNX-JAVA-028](../vnx-java-028/); this rule owns every other shape the two used to report on the same line.

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
stmt.executeQuery("SELECT id FROM orders ORDER BY " + column);

// FLAGGED: after remove(0), index 0 holds the request value
columns.add("id");
columns.add(request.getParameter("col"));
columns.remove(0);
stmt.executeQuery("SELECT id FROM users ORDER BY " + columns.get(0));
```

Anything the analysis cannot resolve stays reported: a condition on run-time data, a call into another class, a collection filled in a loop or handed to another method, a helper that returns (a transform of) its parameter.

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
