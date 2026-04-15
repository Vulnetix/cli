---
title: "VNX-PHP-023 – PHP anonymous LDAP bind without password"
description: "Detects ldap_bind() called without a password, with NULL, or with an empty string, enabling anonymous LDAP access that exposes directory data without authentication."
---

## Overview

This rule detects calls to PHP's `ldap_bind()` function where the password argument is absent, `NULL`, or an empty string. LDAP servers that permit anonymous binds allow unauthenticated clients to search the directory with whatever read permissions the anonymous access control list grants. In many default LDAP and Active Directory configurations, anonymous users can read a substantial portion of the directory schema and user data.

There are two forms of unintended anonymous bind. The first is an explicit anonymous bind — calling `ldap_bind($conn)` with only one argument. The second is an accidental anonymous bind — calling `ldap_bind($conn, $dn, '')` with an empty password string. LDAP protocol specifies that a bind with a non-empty DN but an empty password must be treated as an anonymous bind (RFC 4513, Section 5.1.2), meaning applications that validate the password before binding but fail to check for empty strings will silently authenticate anonymously rather than rejecting the empty password.

The second form is particularly dangerous because it looks like authenticated code — the DN is provided — but behaves as anonymous because of the empty password. This can occur when a user submits a blank password in a login form and the application passes it directly to `ldap_bind()`.

**Severity:** High | **CWE:** [CWE-287 – Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

## Why This Matters

Anonymous LDAP access in enterprise environments exposes user account information including usernames, email addresses, phone numbers, department assignments, and group memberships. In Active Directory environments, anonymous or low-privileged LDAP enumeration is frequently the first step in a domain reconnaissance phase following initial access.

The empty-password anonymous bind issue enables authentication bypass. If a web application accepts a blank password from a login form and passes it to `ldap_bind()` expecting an authentication failure but instead receives an anonymous bind success, any user can log in to any account by submitting a blank password. This type of vulnerability has appeared in real-world authentication systems and allowed complete account takeover for any user in the directory.

For service account binds, using a hardcoded empty password or no password at all exposes the directory to any client that can reach the LDAP port.

## What Gets Flagged

```php
// FLAGGED: anonymous bind — no DN or password provided
ldap_bind($conn);

// FLAGGED: empty password — treated as anonymous bind by LDAP protocol
ldap_bind($conn, $userDn, '');
ldap_bind($conn, $userDn, null);

// FLAGGED: password from user input could be empty, bypassing auth
ldap_bind($conn, 'cn=' . $_POST['username'] . ',dc=example,dc=com', $_POST['password']);
```

## Remediation

1. **Always call `ldap_bind()` with a DN and a non-empty password** for service account connections.

2. **Explicitly check that the password is non-empty** before passing it to `ldap_bind()` — reject authentication attempts with blank passwords before the LDAP call.

3. **Store service account credentials in environment variables or a secrets manager**, not in source code.

4. **Disable anonymous binds on the LDAP server** via access control lists so that anonymous connections cannot read directory data.

```php
<?php
// SAFE: service bind uses credentials from environment
$conn = ldap_connect($_ENV['LDAP_HOST']);
ldap_set_option($conn, LDAP_OPT_PROTOCOL_VERSION, 3);

$bindDn  = $_ENV['LDAP_SERVICE_DN'];
$bindPw  = $_ENV['LDAP_SERVICE_PASSWORD'];

if (empty($bindPw)) {
    throw new RuntimeException('LDAP service password must not be empty');
}

if (!ldap_bind($conn, $bindDn, $bindPw)) {
    throw new RuntimeException('LDAP service bind failed');
}

// SAFE: user authentication — reject empty passwords explicitly
function authenticateUser(string $username, string $password, $conn): bool {
    if (empty($password)) {
        return false; // never attempt bind with empty password
    }
    $dn = 'uid=' . ldap_escape($username, '', LDAP_ESCAPE_DN) . ',dc=example,dc=com';
    return @ldap_bind($conn, $dn, $password);
}
```

## References

- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [CAPEC-116: Excavation](https://capec.mitre.org/data/definitions/116.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [RFC 4513 – LDAP Authentication Methods and Security Mechanisms](https://datatracker.ietf.org/doc/html/rfc4513#section-5.1.2)
- [PHP Manual – ldap_bind()](https://www.php.net/manual/en/function.ldap-bind.php)
