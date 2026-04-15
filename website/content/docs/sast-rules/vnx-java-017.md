---
title: "VNX-JAVA-017 – Java HTTP Response Splitting via Unsanitised Header Value"
description: "Detect Java servlet and Spring code that passes user-controlled request parameters directly to addHeader(), setHeader(), or sendRedirect() without stripping CR and LF characters, enabling HTTP response splitting and header injection attacks."
---

## Overview

This rule flags Java servlet and Spring handler code where a value sourced from user input — via `getParameter()`, `getHeader()`, `getQueryString()`, `getPathInfo()`, or `getAttribute()` — is passed to `response.addHeader()`, `response.setHeader()`, or `response.sendRedirect()` without stripping carriage-return (`\r`, `%0d`) and line-feed (`\n`, `%0a`) characters. This maps to [CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers](https://cwe.mitre.org/data/definitions/113.html).

**Severity:** High | **CWE:** [CWE-113 – HTTP Response Splitting](https://cwe.mitre.org/data/definitions/113.html)

## Why This Matters

HTTP headers are delimited by `\r\n` sequences. If user-supplied text containing these characters reaches a header or redirect URL, an attacker can:

- **Inject arbitrary HTTP headers** — for example, injecting `Set-Cookie` to fix a session token (session fixation).
- **Split the response into two** — the second response is entirely attacker-controlled and served to a caching proxy, enabling **cache poisoning** that affects subsequent users.
- **Conduct Cross-Site Scripting (XSS)** — injecting a second response body with an HTML/JavaScript payload served to the browser.
- **Bypass security controls** — overwriting security headers like `Content-Security-Policy` or `X-Frame-Options` with permissive values.

**OWASP ASVS v4.0 requirements:**

- **V5.2.1** — Verify that all untrusted HTML input is properly sanitized.
- **V14.4.1** — Verify that every HTTP response contains a `Content-Type` header specifying a safe character set.

**Real-world CVEs:**

- CVE-2011-2092 — Adobe BlazeDS HTTP response splitting via unsanitised `Destination` header value.
- CVE-2020-13933 — Apache Shiro redirect URL injection enabling response splitting.
- CVE-2016-4430 — Apache Struts open redirect and response splitting via `redirect:` prefix.

## What Gets Flagged

```java
// FLAGGED: user-controlled value passed directly to setHeader()
String lang = request.getParameter("lang");
response.setHeader("Content-Language", lang);

// FLAGGED: user-controlled value in sendRedirect()
String returnUrl = request.getParameter("returnUrl");
response.sendRedirect(returnUrl); // \n in returnUrl splits the response

// FLAGGED: addHeader() with user-supplied header relay
String referrer = request.getHeader("Referer");
response.addHeader("X-Referer-Echo", referrer);
```

## Remediation

Strip or reject `\r` and `\n` from any user-supplied string before it reaches a header or redirect URL.

**Minimal CRLF sanitization:**

```java
// SAFE: strip CR and LF before setting any header value
private static String sanitizeHeader(String value) {
    if (value == null) return null;
    return value.replaceAll("[\r\n]", "");
}

String lang = sanitizeHeader(request.getParameter("lang"));
response.setHeader("Content-Language", lang);
```

**Allowlist validation for redirect URLs (preferred):**

```java
// SAFE: only allow relative paths or known safe hosts
private static final Set<String> ALLOWED_HOSTS = Set.of("example.com", "app.example.com");

String returnUrl = request.getParameter("returnUrl");
try {
    URI uri = new URI(returnUrl);
    if (uri.isAbsolute() && !ALLOWED_HOSTS.contains(uri.getHost())) {
        returnUrl = "/";
    }
} catch (URISyntaxException e) {
    returnUrl = "/";
}
// Defence-in-depth: strip CRLF even after allowlist check
returnUrl = returnUrl.replaceAll("[\r\n]", "");
response.sendRedirect(returnUrl);
```

**OWASP Java Encoder library** — provides purpose-built encoders for URL components that handle CRLF:

```java
import org.owasp.encoder.Encode;

// SAFE: encode for use in a header value context
String safe = Encode.forJava(request.getParameter("lang"));
response.setHeader("Content-Language", safe);
```

**Spring Security note:** Spring Security 5+ `HeaderWriterFilter` adds security response headers automatically, but it does not sanitize user-supplied header values. CRLF protection must be applied at the application layer before calling `setHeader()` or `sendRedirect()`.

Modern Servlet containers (Tomcat 9+, Jetty 10+) reject raw CRLF in header values by default. However, URL-encoded variants (`%0d%0a`) may be decoded by browsers or intermediate proxies before the raw bytes reach the container — always sanitize regardless of container version.

## References

- [CWE-113: HTTP Response Splitting](https://cwe.mitre.org/data/definitions/113.html)
- [CAPEC-34: HTTP Response Splitting](https://capec.mitre.org/data/definitions/34.html)
- [OWASP HTTP Response Splitting](https://owasp.org/www-community/attacks/HTTP_Response_Splitting)
- [OWASP Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [OWASP Java Encoder Project](https://owasp.org/www-project-java-encoder/)
- [OWASP ASVS v4.0 – V5 Validation, Sanitization and Encoding](https://owasp.org/www-project-application-security-verification-standard/)
