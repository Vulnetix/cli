---
title: "VNX-JAVA-012 – Java LDAP Injection"
description: "Detects Java JNDI/LDAP search calls that incorporate user-controlled request parameters directly into LDAP filter strings, enabling authentication bypass and directory data exfiltration."
---

## Overview

This rule detects calls to `DirContext.search()`, `ctx.search()`, or `dirContext.search()` where the LDAP filter argument includes a value read directly from `request.getParameter()` or `req.getParameter()`, as well as patterns where LDAP filter syntax characters are concatenated around a parameter value. Unsanitized user input in an LDAP filter enables LDAP injection (CWE-90), allowing attackers to alter the filter logic, bypass authentication, and exfiltrate directory entries.

**Severity:** High | **CWE:** [CWE-90 – Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')](https://cwe.mitre.org/data/definitions/90.html)

## Why This Matters

LDAP is commonly used for authentication and authorisation in enterprise applications — particularly those backed by Active Directory or OpenLDAP. LDAP injection attacks against authentication filters are analogous to SQL injection against login queries: by manipulating the filter logic the attacker can authenticate as any user, including administrators.

A filter like `(&(uid=` + username + `)(userPassword=` + password + `))` is vulnerable. Supplying a username of `admin)(&(` causes the filter to become `(&(uid=admin)(&()(userPassword=anything))` — the wildcard sub-filter always evaluates to true, granting access as `admin` regardless of the password. More sophisticated payloads can enumerate all users and groups by exploiting the filter's boolean logic, disclosing the entire directory tree structure including email addresses, phone numbers, manager hierarchies, and group memberships.

JNDI lookups (particularly in Log4j-style contexts) can also trigger network requests to attacker-controlled LDAP servers, leading to JNDI/RCE as demonstrated by Log4Shell — though that attack vector is distinct from the filter injection detected by this rule.

## What Gets Flagged

The rule matches direct parameter-to-search calls and concatenation patterns in LDAP filter strings.

```java
// FLAGGED: user input directly in search() filter
String username = request.getParameter("username");
NamingEnumeration results = ctx.search("ou=users,dc=example,dc=com",
    "(uid=" + username + ")", searchControls);

// FLAGGED: filter construction with concatenation
String filter = "(&(objectClass=person)(cn=" + request.getParameter("name") + "))";
dirContext.search("dc=example,dc=com", filter, controls);

// FLAGGED: direct parameter as filter argument
ctx.search(baseDn, request.getParameter("filter"), searchControls);
```

## Remediation

1. **Encode all user-supplied values using LDAP filter encoding before inserting them into a filter.** LDAP special characters that must be escaped in filter values are: `*`, `(`, `)`, `\`, `NUL`. Encode each as a backslash-hex sequence. The Spring LDAP library provides `org.springframework.ldap.filter` classes that handle encoding automatically.

   ```java
   // SAFE: Spring LDAP filter API with automatic encoding
   import org.springframework.ldap.filter.AndFilter;
   import org.springframework.ldap.filter.EqualsFilter;

   AndFilter filter = new AndFilter();
   filter.and(new EqualsFilter("objectClass", "person"));
   filter.and(new EqualsFilter("uid", request.getParameter("username")));
   // filter.encode() produces a safe, encoded filter string
   String encodedFilter = filter.encode();
   NamingEnumeration results = ctx.search("ou=users,dc=example,dc=com",
       encodedFilter, searchControls);
   ```

2. **If you use raw filter strings, manually escape the value using `LdapEncoder.filterEncode()`.** Spring LDAP exposes this utility if the full filter builder API is not convenient:

   ```java
   // SAFE: manual encoding of the user-supplied value
   import org.springframework.ldap.core.support.LdapEncoder;

   String safeUid = LdapEncoder.filterEncode(request.getParameter("username"));
   String filter = "(&(objectClass=person)(uid=" + safeUid + "))";
   ctx.search(baseDn, filter, searchControls);
   ```

3. **Use Spring LDAP's `LdapTemplate` for all LDAP operations.** `LdapTemplate` provides a higher-level, Spring-idiomatic API that encourages the use of filter builder objects and handles connection lifecycle. Pair it with `org.springframework.ldap.query.LdapQueryBuilder` for a fully safe query API:

   ```java
   // SAFE: LdapQueryBuilder — type-safe and injection-proof
   import static org.springframework.ldap.query.LdapQueryBuilder.query;

   List<String> users = ldapTemplate.search(
       query()
           .base("ou=users,dc=example,dc=com")
           .where("objectClass").is("person")
           .and("uid").is(request.getParameter("username")),
       (Attributes attrs) -> (String) attrs.get("cn").get()
   );
   ```

4. **Validate input with an allowlist before any LDAP operation.** UIDs and CNs in most directories contain only alphanumeric characters and a small set of punctuation. Reject any input containing LDAP metacharacters (`*`, `(`, `)`, `\`, `NUL`) before the value reaches the LDAP layer at all.

   ```java
   // SAFE: allowlist validation on username format
   String username = request.getParameter("username");
   if (username == null || !username.matches("[a-zA-Z0-9._@-]{1,64}")) {
       throw new IllegalArgumentException("Invalid username format");
   }
   ```

5. **Restrict the LDAP service account's permissions.** The account used by the application to bind to LDAP should be a read-only service account with access limited to the specific OUs and attributes the application requires. Never use the directory administrator account.

6. **Encode LDAP output before displaying it.** If attribute values read from LDAP are rendered in HTML, encode them for the output context (HTML-encode for web pages) to prevent stored XSS through directory data.

## References

- [CWE-90: Improper Neutralization of Special Elements used in an LDAP Query](https://cwe.mitre.org/data/definitions/90.html)
- [CAPEC-136: LDAP Injection](https://capec.mitre.org/data/definitions/136.html)
- [MITRE ATT&CK T1190 – Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [OWASP LDAP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html)
- [Spring LDAP – Filter Classes](https://docs.spring.io/spring-ldap/docs/current/reference/html/#filters)
- [Spring LDAP – LdapQueryBuilder](https://docs.spring.io/spring-ldap/docs/current/reference/html/#query-builder-api)
- [OWASP ASVS V5 – Validation, Sanitization and Encoding](https://owasp.org/www-project-application-security-verification-standard/)
