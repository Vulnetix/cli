---
title: "VNX-KOTLIN-003 – Kotlin Cookie Missing HttpOnly Flag"
description: "Detects Kotlin session and credential cookies sent without HttpOnly (servlet, Spring ResponseCookie, Ktor, Javalin, http4k, Micronaut, raw Set-Cookie headers) and HttpOnly explicitly disabled, so injected scripts cannot steal them."
---

## Overview

The `HttpOnly` attribute on a cookie instructs the browser to prevent JavaScript from reading the cookie's value via `document.cookie`. Without this attribute, any cross-site scripting (XSS) vulnerability — even a minor reflected XSS in a minor feature — can be used to steal session cookies and hijack authenticated sessions. This is CWE-1004 (Sensitive Cookie Without 'HttpOnly' Flag).

This rule flags two patterns in Kotlin files (`.kt`, `.kts`):

- **HttpOnly explicitly disabled:** `cookie.setHttpOnly(false)`, `cookie.isHttpOnly = false` (or `isHttpOnly = false` in an `apply` block), `servletContext.sessionCookieConfig.isHttpOnly = false`, Spring `ResponseCookie...httpOnly(false)`, Spring Session `setUseHttpOnlyCookie(false)`, Ktor `Cookie(..., httpOnly = false)` and Ktor Sessions `cookie.httpOnly = false`.
- **A credential cookie sent with no HttpOnly setting at all:** a cookie whose name or value names a session, token, JWT, auth, login, remember-me or similar credential, passed to `response.addCookie()`, Ktor `call.response.cookies.append()`, Javalin `ctx.cookie()`, http4k `Response.cookie()` or Micronaut `HttpResponse.cookie()` (built inline, or in a variable constructed up to 25 lines above with nothing in between setting HttpOnly), Ktor `cookies.append(name, value)` and Javalin `ctx.cookie(name, value)` (both default to not HttpOnly), a Spring `ResponseCookie.from(...)` chain built without `.httpOnly(true)`, and a raw `Set-Cookie` header literal that omits `HttpOnly`.

It does not report cookies that set HttpOnly true anywhere between construction and the response, cookies that scripts are meant to read (theme, locale, UI flags), CSRF/XSRF double-submit token cookies, Ktor Sessions with their HttpOnly default, cookies built by a helper function or passed in as a parameter, client-side cookie jars (OkHttp `Cookie.Builder`), reading a cookie (`ctx.cookie("session")`), test sources, comments and string literals.

Session hijacking via XSS and cookie theft is one of the most well-understood and widely exploited attack chains in web security. The HttpOnly flag is a one-line fix that eliminates the cookie-theft vector entirely, making it one of the highest-return security controls available.

**Severity:** Medium | **CWE:** [CWE-1004 – Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)

## Why This Matters

When an attacker finds an XSS vulnerability in a web application, their first action is typically to steal session cookies using `document.cookie` and send them to an external server. With the session cookie, the attacker can impersonate the victim without knowing their password, bypassing multi-factor authentication entirely because the session was already authenticated.

The attack is particularly dangerous because XSS vulnerabilities are common in large applications, and a single vulnerable endpoint is sufficient regardless of how many other endpoints are properly secured. A XSS in a low-privilege feature like a comment field or search box can be used to steal the session cookie of an administrator if that administrator views the affected page.

Kotlin applications targeting the JVM or Android may use `javax.servlet.http.Cookie` or Ktor's cookie DSL. Both are covered by this rule. In Ktor, the equivalent is setting `httpOnly = true` in the cookie configuration block.

## What Gets Flagged

```kotlin
// FLAGGED: HttpOnly explicitly disabled
val cookie = Cookie("auth_token", sessionToken)
cookie.setHttpOnly(false)

// FLAGGED (the addCookie line): session cookie sent without HttpOnly
val cookie = Cookie("SESSIONID", session.id)
cookie.secure = true
response.addCookie(cookie)

// FLAGGED: Ktor and Javalin name/value forms default to not HttpOnly
call.response.cookies.append("session_id", sessionId)
ctx.cookie("session_id", sessionId)

// FLAGGED: Spring builder without .httpOnly(true)
val refresh = ResponseCookie.from("refresh_token", refreshToken)
    .secure(true)
    .build()

// FLAGGED: Ktor Sessions with HttpOnly turned off
cookie<UserSession>("user_session") { cookie.httpOnly = false }
```

Not flagged:

```kotlin
response.addCookie(Cookie("theme", theme))                 // not a credential
Cookie("XSRF-TOKEN", csrfToken).apply { isHttpOnly = false } // double-submit token
call.response.cookies.append(Cookie("session", id, httpOnly = true, secure = true))
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
