---
title: "VNX-JAVA-015 – Java JPQL/HQL Injection via String Concatenation"
description: "Detect Java code that builds JPQL, HQL, or native SQL queries using string concatenation in EntityManager.createQuery() or Session.createQuery(), enabling query injection."
---

## Overview

This rule flags Java code where `createQuery()`, `createNativeQuery()`, or `createNamedQuery()` constructs queries using string concatenation (`+`) or `String.format()`. These patterns enable injection attacks where an attacker can manipulate the query structure to read, modify, or delete data they should not have access to. This maps to [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html).

**Severity:** High | **CWE:** [CWE-89 – SQL Injection](https://cwe.mitre.org/data/definitions/89.html)

## Why This Matters

JPA and Hibernate use JPQL/HQL as their query languages, which look similar to SQL. Developers often assume these are "safe" because they abstract the database — but JPQL/HQL injection is just as dangerous as SQL injection. An attacker can extract arbitrary entity data, modify records, or in the case of `createNativeQuery()`, execute raw SQL including administrative commands.

## What Gets Flagged

```java
// FLAGGED: JPQL query built with string concatenation
em.createQuery("SELECT u FROM User u WHERE u.name = '" + name + "'");

// FLAGGED: native SQL with String.format
em.createNativeQuery(String.format("SELECT * FROM users WHERE id = %s", id));
```

## Remediation

1. **Use named parameters with `setParameter()`:**

```java
// SAFE: parameterized JPQL query
TypedQuery<User> query = em.createQuery(
    "SELECT u FROM User u WHERE u.name = :name", User.class);
query.setParameter("name", userInput);
```

2. **Use positional parameters for native queries:**

```java
// SAFE: positional parameters
Query query = em.createNativeQuery("SELECT * FROM users WHERE id = ?1");
query.setParameter(1, userId);
```

3. **Use the JPA Criteria API** for dynamic queries that are type-safe and injection-free by construction.

## References

- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [JPA JPQL documentation](https://jakarta.ee/specifications/persistence/3.1/jakarta-persistence-spec-3.1#a4665)
- [Hibernate HQL documentation](https://docs.jboss.org/hibernate/orm/6.4/userguide/html_single/Hibernate_User_Guide.html#query-language)
- [CAPEC-66: SQL Injection](https://capec.mitre.org/data/definitions/66.html)
