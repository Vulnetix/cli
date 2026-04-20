---
title: "VNX-90 – LDAP Injection"
description: "Detect user-controlled data concatenated into LDAP filter strings without sanitization, enabling directory enumeration or authentication bypass."
---

## Overview

This rule flags LDAP search operations where user-controlled data is concatenated into LDAP filter strings without sanitization. An attacker can inject LDAP metacharacters (`*`, `(`, `)`, `\`, `NUL`) to modify the filter logic, bypass authentication, enumerate directory entries, or escalate privileges. This maps to [CWE-90: Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')](https://cwe.mitre.org/data/definitions/90.html).

**Severity:** High | **CWE:** [CWE-90 – LDAP Injection](https://cwe.mitre.org/data/definitions/90.html)

## Why This Matters

LDAP directories are commonly used for enterprise authentication (Active Directory, OpenLDAP). An LDAP injection that modifies the filter `(&(uid=alice)(password=secret))` to `(&(uid=*)(password=*))` authenticates any user regardless of password. Attackers can also use `)(uid=*)` to extract all users from the directory.

## What Gets Flagged

```java
// FLAGGED: Java — concatenated LDAP filter
String uid = request.getParameter("uid");
NamingEnumeration results = ctx.search("ou=users,dc=example,dc=com",
    "(&(uid=" + uid + ")(objectClass=person))", controls);
```

```python
# FLAGGED: Python ldap3 with user input
username = request.args['username']
connection.search('ou=users,dc=example,dc=com',
    f'(uid={username})', attributes=['cn', 'mail'])
```

```php
<?php
// FLAGGED: PHP ldap_search with superglobal
$filter = "(&(uid=" . $_GET['user'] . "))";
$result = ldap_search($conn, "ou=users,dc=example,dc=com", $filter);
```

```javascript
// FLAGGED: Node.js ldapjs with req.body
const filter = `(&(uid=${req.body.username})(objectClass=person))`;
client.search('ou=users,dc=example,dc=com', { filter }, (err, res) => { ... });
```

## Remediation

1. **Escape special characters** before inserting user data into LDAP filters.

```java
// SAFE: Java — use JNDI filter escaping
import javax.naming.directory.SearchControls;
// Escape special chars: ( ) * \ NUL
String safeUid = uid.replaceAll("[\\\\\\(\\)\\*\\x00]", "\\\\$0");
NamingEnumeration results = ctx.search(base, "(&(uid=" + safeUid + "))", controls);
```

```python
# SAFE: Python — ldap.filter.escape_filter_chars
import ldap.filter
safe_user = ldap.filter.escape_filter_chars(username)
conn.search(base_dn, f'(uid={safe_user})', attributes=['cn'])
```

```php
<?php
// SAFE: PHP — ldap_escape with LDAP_ESCAPE_FILTER
$safe = ldap_escape($_GET['user'], '', LDAP_ESCAPE_FILTER);
$filter = "(&(uid=$safe))";
$result = ldap_search($conn, $base, $filter);
```

```javascript
// SAFE: Node.js — escape LDAP filter characters
function escapeLdap(str) {
    return str.replace(/[\\*().\x00]/g, c => `\\${c.charCodeAt(0).toString(16).padStart(2,'0')}`);
}
const filter = `(&(uid=${escapeLdap(req.body.username)}))`;
```

2. **Use parameterised LDAP libraries** where available.

3. **Apply the principle of least privilege** to the LDAP service account used by the application.

## References

- [CWE-90: LDAP Injection](https://cwe.mitre.org/data/definitions/90.html)
- [OWASP LDAP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html)
- [CAPEC-136: LDAP Injection](https://capec.mitre.org/data/definitions/136.html)
