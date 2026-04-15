---
title: "VNX-JAVA-025 – Java Hardcoded Password or Credential"
description: "Detects passwords, credentials, and database connection strings hardcoded as string literals in Java source code, which can be extracted from source or compiled binaries and are difficult to rotate."
---

## Overview

Hardcoded credentials are among the most commonly exploited vulnerability patterns in enterprise Java applications. When a password, API key, or database connection string is written as a string literal in source code — `String password = "Sup3rS3cr3t!"` or `DriverManager.getConnection("jdbc:mysql://db/app", "admin", "admin123")` — it becomes permanently embedded in the version control history, compiled into the class file, and visible to anyone with access to the source repository or the JAR. This is CWE-259 (Use of Hard-coded Password).

This rule flags two patterns: variable assignments where the left-hand side name matches `password`, `passwd`, or `pwd` and the right-hand side is a non-trivial string literal (excluding lines that use `getParameter`, `getenv`, `@Value`, or comments), and `DriverManager.getConnection()` calls with all three arguments as string literals. Both patterns indicate credentials that are not externalized and therefore cannot be rotated without a code change.

Hardcoded credentials are particularly dangerous in microservice architectures where dozens of services may share a single database credential. Rotating a hardcoded credential requires rebuilding and redeploying every service that contains it.

**Severity:** Critical | **CWE:** [CWE-259 – Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)

## Why This Matters

Public GitHub repositories are continuously scanned by automated tools and threat actors looking for hardcoded credentials. Within minutes of pushing a commit that includes a database password or API key, that credential can be found and exploited. Even private repositories are at risk: former employees, compromised developer accounts, and accidental repository visibility changes have all been sources of credential exposure.

Compiled Java artifacts also expose hardcoded credentials. JAR and WAR files can be decompiled with freely available tools such as CFR or Fernflower in seconds, yielding readable source code complete with string literals. A QA or staging artifact shared with an external vendor can expose production credentials if the same values are used across environments.

A 2023 GitGuardian report found hardcoded credentials in over 10 million public GitHub commits. The Uber 2016 breach and numerous AWS credential exposures have involved hardcoded credentials committed to source control.

## What Gets Flagged

```java
// FLAGGED: password assigned as a string literal
private static final String password = "Sup3rS3cr3t!";

// FLAGGED: database credentials hardcoded in getConnection
Connection conn = DriverManager.getConnection(
    "jdbc:mysql://db.internal/app", "dbadmin", "dbpassword123");

// FLAGGED: credential in constructor
new BasicCredentialsProvider().setCredentials(
    AuthScope.ANY, new UsernamePasswordCredentials("user", "hardcoded_pass"));
```

## Remediation

1. **Externalize credentials to environment variables** and read them at runtime with `System.getenv()`.

2. **Use a secrets manager** (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault) and inject the retrieved secret at startup, never storing it in source code.

3. **In Spring applications**, use `@Value("${db.password}")` with properties sourced from an external configuration server (Spring Cloud Config, Kubernetes Secrets).

4. **Audit git history** and rotate any credentials found in past commits immediately. `git log -S "password"` can surface historical occurrences.

```java
// SAFE: credentials from environment variables
String dbPassword = Objects.requireNonNull(
    System.getenv("DB_PASSWORD"), "DB_PASSWORD environment variable not set");
Connection conn = DriverManager.getConnection(jdbcUrl, dbUser, dbPassword);
```

```java
// SAFE: Spring externalized configuration
@Value("${datasource.password}")
private String dataSourcePassword;
```

```java
// SAFE: AWS Secrets Manager at startup
SecretsManagerClient client = SecretsManagerClient.create();
GetSecretValueResponse secret = client.getSecretValue(
    GetSecretValueRequest.builder().secretId("prod/db/password").build());
String dbPassword = secret.secretString();
```

## References

- [CWE-259: Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)
- [OWASP Java Security Cheat Sheet – Secrets Management](https://cheatsheetseries.owasp.org/cheatsheets/Java_Security_Cheat_Sheet.html)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [Spring Security: Externalized Configuration](https://docs.spring.io/spring-boot/reference/features/external-config.html)
- [MITRE ATT&CK T1552: Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)
