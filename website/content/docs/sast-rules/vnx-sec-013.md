---
title: "VNX-SEC-013 – Insecure Cookie Configuration"
description: "Detects cookies whose HttpOnly or Secure protection is switched off, and session or authentication cookies issued without HttpOnly, across Node, Python, Go, Java, .NET, PHP and Ruby."
---

## Overview

This rule reports a cookie whose HttpOnly or Secure protection is switched off: `httpOnly: false` / `secure: false` in cookie or session options (Express, Go `http.Cookie` and gorilla `sessions.Options`, ASP.NET `CookieOptions`, Rails `session_store`, Spring YAML), Django and Flask `SESSION_COOKIE_SECURE` / `SESSION_COOKIE_HTTPONLY` / `CSRF_COOKIE_SECURE = False`, `set_cookie(..., secure=False)`, Java `setHttpOnly(false)` / `setSecure(false)`, Spring `server.servlet.session.cookie.*=false`, `CookieSecurePolicy.None`, web.config `httpOnlyCookies="false"`, PHP `ini_set('session.cookie_httponly', 0)` and php.ini, and `false` as the secure/httponly argument of PHP `setcookie()` or gin's `c.SetCookie()`. It also reports a session, token, auth, JWT, remember-me or user-id cookie issued with no HttpOnly setting at all (`res.cookie('session', id)`, `set_cookie('token', t)`, a Go `http.Cookie{}` with no `HttpOnly` field, Java `new Cookie("access_token", t)` with no `setHttpOnly`, PHP `setcookie('appSession', $v)`). It does not report the CSRF/XSRF cookie's HttpOnly (the page must read it), theme or language cookies, flags read from variables or the environment, options passed as a variable, cookies being cleared, development settings files, tests and documentation. SameSite is not checked. These settings control three distinct attack surfaces: HttpOnly prevents JavaScript from reading the cookie (blocking XSS-based session theft), Secure ensures the cookie is only sent over HTTPS (blocking cleartext interception), and SameSite restricts cross-origin sending (blocking CSRF).

**Severity:** Medium | **CWE:** [CWE-614 – Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html), [CWE-1004 – Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)

## Why This Matters

Session cookies are the keys to your users' authenticated sessions. When any of the three security flags are missing or explicitly disabled:

- **No HttpOnly**: A single XSS vulnerability anywhere on your site becomes a full account takeover — malicious scripts can run `document.cookie` to extract the session token and exfiltrate it to an attacker's server.
- **No Secure**: Session tokens are transmitted in cleartext over HTTP connections. On untrusted networks (coffee shops, airports), attackers using network sniffers or tools like Wireshark can capture and replay session tokens.
- **No SameSite (or `SameSite=None`)**: Cross-site requests automatically include the cookie, enabling CSRF attacks. An attacker can host a page that makes authenticated requests to your application using the victim's session.

Many frameworks set these flags to `False` by default in development for convenience, but production deployments that inherit development configurations become vulnerable.

## What Gets Flagged

```python
# FLAGGED: Django insecure cookie settings
SESSION_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = False
CSRF_COOKIE_SECURE = False
```

```javascript
// FLAGGED: Express cookie with security disabled
app.use(session({
    secret: 'keyboard cat',
    cookie: {
        secure: false,
        httpOnly: false,
    }
}));
```

```python
# FLAGGED: Flask insecure session cookie
app.config['SESSION_COOKIE_SECURE'] = False
# FLAGGED: session cookie with no httponly
response.set_cookie("session_id", token)
```

```go
// FLAGGED: no HttpOnly field on a cookie whose name is a parameter
cookie := http.Cookie{
	Name:  name,
	Value: value,
	Path:  "/",
}
```

```php
// FLAGGED: secure and httponly passed as false
setcookie("auth_token", $token, time() + 3600, "/", "", false, false);
```

Not flagged: `res.cookie('XSRF-TOKEN', req.csrfToken(), { httpOnly: false, secure: true })`, `res.cookie('theme', 'dark')`, `secure: process.env.NODE_ENV === 'production'`.

## Remediation

1. **Enable all three flags for session cookies in production.** The goal is `Set-Cookie: session=<value>; HttpOnly; Secure; SameSite=Strict`.

```python
# SAFE: Django secure cookie settings
SESSION_COOKIE_SECURE = True        # HTTPS only
SESSION_COOKIE_HTTPONLY = True      # not accessible to JavaScript
SESSION_COOKIE_SAMESITE = 'Strict'  # block CSRF
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
```

```javascript
// SAFE: Express secure cookie configuration
app.use(session({
    secret: process.env.SESSION_SECRET,
    cookie: {
        secure: true,       // HTTPS only
        httpOnly: true,     // no JavaScript access
        sameSite: 'strict', // block CSRF
        maxAge: 3600000,    // 1 hour
    },
    resave: false,
    saveUninitialized: false,
}));
```

```java
// SAFE: Spring Boot secure cookie configuration
@Configuration
public class SecurityConfig {
    @Bean
    public CookieSameSiteSupplier cookieSameSiteSupplier() {
        return CookieSameSiteSupplier.ofStrict();
    }
    // application.properties:
    // server.servlet.session.cookie.secure=true
    // server.servlet.session.cookie.http-only=true
    // server.servlet.session.cookie.same-site=strict
}
```

```php
// SAFE: PHP secure session cookie parameters
session_set_cookie_params([
    'lifetime' => 3600,
    'path'     => '/',
    'secure'   => true,
    'httponly' => true,
    'samesite' => 'Strict',
]);
session_start();
```

2. **Use environment-aware configuration.** Set `Secure=true` in production but allow `false` in local development only when the local server uses HTTP. Use environment variables to control this:

```python
# SAFE: environment-aware cookie security
import os
SESSION_COOKIE_SECURE = os.environ.get('ENVIRONMENT') == 'production'
```

3. **Understand the three flag behaviours:**
   - `HttpOnly`: Cookie is inaccessible to JavaScript — use for all session cookies
   - `Secure`: Cookie is only sent over HTTPS — required in production
   - `SameSite=Strict`: Cookie not sent on cross-site requests — strongest CSRF protection; use `Lax` if you need cookies sent on top-level navigation (e.g., OAuth redirects)

4. **Set `SameSite=Lax` as a minimum** for session cookies if `Strict` breaks your login flow. `None` requires `Secure` to be set as well (browsers enforce this).

## References

- [CWE-614: Sensitive Cookie in HTTPS Session Without Secure Attribute](https://cwe.mitre.org/data/definitions/614.html)
- [CWE-1004: Sensitive Cookie Without HttpOnly Flag](https://cwe.mitre.org/data/definitions/1004.html)
- [OWASP: Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [MDN: Set-Cookie – SameSite attribute](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite)
- [MITRE ATT&CK T1539 – Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
- [CAPEC-31: Accessing/Intercepting/Modifying HTTP Cookies](https://capec.mitre.org/data/definitions/31.html)
