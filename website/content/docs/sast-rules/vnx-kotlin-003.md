---
title: "VNX-KOTLIN-003 – Kotlin Cookie Missing HttpOnly Flag"
description: "Detects cookies added to HTTP responses in Kotlin without the HttpOnly flag, making session cookies readable by client-side JavaScript and vulnerable to XSS-based session hijacking."
---

## Overview

The `HttpOnly` attribute on a cookie instructs the browser to prevent JavaScript from reading the cookie's value via `document.cookie`. Without this attribute, any cross-site scripting (XSS) vulnerability — even a minor reflected XSS in a minor feature — can be used to steal session cookies and hijack authenticated sessions. This is CWE-1004 (Sensitive Cookie Without 'HttpOnly' Flag).

This rule flags two patterns in Kotlin files: explicit `setHttpOnly(false)` calls (a deliberate disablement), and `response.addCookie()` calls on lines that do not also call `setHttpOnly` or reference `httpOnly`. The first pattern is always a finding; the second is a finding when the HttpOnly configuration is not performed on the same logical statement.

Session hijacking via XSS and cookie theft is one of the most well-understood and widely exploited attack chains in web security. The HttpOnly flag is a one-line fix that eliminates the cookie-theft vector entirely, making it one of the highest-return security controls available.

**Severity:** Medium | **CWE:** [CWE-1004 – Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)

## Why This Matters

When an attacker finds an XSS vulnerability in a web application, their first action is typically to steal session cookies using `document.cookie` and send them to an external server. With the session cookie, the attacker can impersonate the victim without knowing their password, bypassing multi-factor authentication entirely because the session was already authenticated.

The attack is particularly dangerous because XSS vulnerabilities are common in large applications, and a single vulnerable endpoint is sufficient regardless of how many other endpoints are properly secured. A XSS in a low-privilege feature like a comment field or search box can be used to steal the session cookie of an administrator if that administrator views the affected page.

Kotlin applications targeting the JVM or Android may use `javax.servlet.http.Cookie` or Ktor's cookie DSL. Both are covered by this rule. In Ktor, the equivalent is setting `httpOnly = true` in the cookie configuration block.

## What Gets Flagged

```kotlin
// FLAGGED: HttpOnly explicitly disabled
val cookie = Cookie("SESSIONID", sessionToken)
cookie.setHttpOnly(false)
response.addCookie(cookie)

// FLAGGED: cookie added without any HttpOnly configuration
val cookie = Cookie("auth_token", token)
response.addCookie(cookie)
```

## Remediation

1. **Always call `setHttpOnly(true)` on cookies that hold session tokens, authentication tokens, or other sensitive values.**

2. **Also set `setSecure(true)`** to prevent the cookie from being transmitted over HTTP.

3. **Set an appropriate `setMaxAge()`** to limit the lifetime of session cookies.

4. **In Ktor**, use the `httpOnly = true` parameter in the cookie DSL.

```kotlin
// SAFE: session cookie with HttpOnly and Secure flags
val sessionCookie = Cookie("SESSIONID", sessionToken).apply {
    isHttpOnly = true
    secure = true
    path = "/"
    maxAge = 3600  // 1 hour
    sameSite = "Strict"
}
response.addCookie(sessionCookie)
```

```kotlin
// SAFE: Ktor cookie with security flags
call.response.cookies.append(
    name = "session",
    value = sessionToken,
    httpOnly = true,
    secure = true,
    path = "/",
    maxAge = Duration.ofHours(1).seconds
)
```

## References

- [CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [Android Developer Security Guide: Network Security](https://developer.android.com/privacy-and-security/security-tips#networking)
- [MDN: HttpOnly Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies)
- [CAPEC-60: Reusing Session IDs (aka Session Replay)](https://capec.mitre.org/data/definitions/60.html)
