---
title: "VNX-PHP-026 – PHP session poisoning via user-controlled session key"
description: "Detects user-controlled input from PHP superglobals used as the key when writing to $_SESSION, enabling session poisoning that can overwrite authentication flags, roles, or CSRF tokens."
---

## Overview

This rule detects two patterns where user-supplied data controls which `$_SESSION` key is written: a direct pattern where `$_SESSION[$_GET['key']]` (or equivalent superglobal) is used as the session key, and an indirect pattern where a variable that was previously assigned from a superglobal is later used as a session key in an assignment statement.

PHP sessions store state in server-side storage keyed by string names that the application chooses. These key names are treated as trusted application constants — code that checks `$_SESSION['authenticated']` or `$_SESSION['role']` assumes those values were set by the application's own authentication logic. When an attacker can control which key is written, they can overwrite any session variable, replacing trusted values with attacker-chosen content.

This class of vulnerability is sometimes called "session poisoning" or "session variable overwrite". It is conceptually similar to mass assignment (VNX-PHP-021) but operates on session state rather than database model attributes. The impact depends on what session variables the application trusts — commonly: `authenticated`, `user_id`, `role`, `is_admin`, `csrf_token`, and `permissions`.

**Severity:** High | **CWE:** [CWE-284 – Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)

## Why This Matters

Session state is the primary mechanism through which PHP applications enforce authentication and authorisation. A vulnerability that allows an attacker to write arbitrary values under arbitrary keys can bypass both. If the attacker can set `$_SESSION['authenticated'] = true` or `$_SESSION['role'] = 'admin'`, they gain the application privileges associated with those values without going through the normal authentication or authorisation flow.

CSRF tokens stored in sessions are also a common target. Overwriting a CSRF token with a known value allows the attacker to forge requests that would otherwise be protected. The attack is particularly subtle because the session overwrite does not generate any authentication event — the application simply finds the expected session variable with an attacker-controlled value and proceeds normally.

The indirect pattern (where the user input is assigned to a variable first, then used as the key) is the harder variant to spot in code review, which is why the rule detects both same-line and multi-line patterns.

## What Gets Flagged

```php
// FLAGGED: superglobal used directly as session key
$_SESSION[$_GET['key']] = $_POST['value'];

// FLAGGED: variable derived from user input used as session key
$key = $_REQUEST['field'];
$_SESSION[$key] = 'true';

// FLAGGED: COOKIE value as session key
$_SESSION[$_COOKIE['pref']] = 1;
```

Attacker request to set `authenticated` key:

```
POST /prefs.php
field=authenticated&value=1
```

## Remediation

1. **Always use hardcoded string constants as `$_SESSION` keys.** Never derive a session key name from user input.

2. **Define session key names as PHP constants** (`const SESSION_USER_ID = 'user_id'`) so they are auditable and consistent.

3. **If a user preference name needs to be stored in the session**, use a hardcoded outer key (e.g., `$_SESSION['preferences']['theme']`) and validate the inner key against a strict allowlist of permitted preference names.

4. **Audit all `$_SESSION[...]` write sites** in the codebase to confirm every key is a literal string or a defined constant.

```php
<?php
// SAFE: all session keys are hardcoded string literals
$_SESSION['user_id']       = $authenticatedUserId;
$_SESSION['role']          = $userRole;
$_SESSION['authenticated'] = true;

// SAFE: user preference stored under a hardcoded outer key
//       with the preference name validated against an allowlist
$allowedPrefs = ['theme', 'language', 'notifications'];
$prefName = $_POST['pref'] ?? '';

if (in_array($prefName, $allowedPrefs, true)) {
    $_SESSION['preferences'][$prefName] = $_POST['value'];
}
// Attacker cannot set $_SESSION['authenticated'] through this path
// because 'authenticated' is not in $allowedPrefs
```

## References

- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- [CAPEC-61: Session Fixation](https://capec.mitre.org/data/definitions/61.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [PHP Manual – Sessions](https://www.php.net/manual/en/book.session.php)
- [OWASP Testing Guide – Testing for Session Puzzling](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/06-Session_Management_Testing/08-Testing_for_Session_Puzzling)
