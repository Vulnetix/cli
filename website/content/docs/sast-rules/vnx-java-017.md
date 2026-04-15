---
title: "VNX-JAVA-017 – Java HTTP response splitting via unsanitised header value"
description: "Detects Java servlet and Spring code that passes user-controlled request parameters directly to addHeader(), setHeader(), or sendRedirect() without stripping CR and LF characters, enabling HTTP response splitting and header injection."
---

## Overview

This rule detects patterns where user-supplied input — read via `getParameter()`, `getHeader()`, `getQueryString()`, `getPathInfo()`, or `getAttribute()` — flows directly into an HTTP response header via `addHeader()`, `setHeader()`, or into a redirect URL via `sendRedirect()`. When carriage-return (`\r`, `%0D`) and line-feed (`\n`, `%0A`) characters are not stripped from such input, an attacker can inject these control characters to break the HTTP response into two separate responses, a technique known as HTTP Response Splitting (CWE-113).

HTTP headers are delimited by CRLF sequences. A server that places attacker-controlled data containing `\r\n` into a response header effectively allows the attacker to terminate the first response and write the headers and body of an entirely new, second response. From the browser's perspective, it has received two responses: the legitimate one and the injected one.

The attack surface extends to caches as well. If a reverse proxy or CDN sits between the server and the client, the injected second response can be stored in the cache and served to subsequent users who request a completely unrelated resource — a technique known as cache poisoning.

**Severity:** High | **CWE:** [CWE-113 – Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')](https://cwe.mitre.org/data/definitions/113.html)

## Why This Matters

HTTP Response Splitting combines header injection with browser behavior and caching to enable multiple distinct attacks. In a cookie injection attack, an adversary adds a `Set-Cookie` header to the injected response, overwriting the victim's session cookie with attacker-controlled values. This can be used to fix a known session ID (session fixation) before the victim authenticates.

In a cross-site scripting variant, the attacker injects a complete second response with a `Content-Type: text/html` header and a body containing `<script>` tags. Because the response origin matches the target application's domain, the browser executes the script in the context of that origin, bypassing the same-origin policy.

Cache poisoning takes the attack further: a single successful request from the attacker can inject a poisoned response that is cached and served to thousands of subsequent visitors, effectively defacing the site or harvesting credentials at scale without any ongoing attacker involvement.

## What Gets Flagged

```java
// FLAGGED: user-supplied header value passed directly to setHeader()
String lang = request.getParameter("lang");
response.setHeader("Content-Language", lang); // \r\n in lang splits the response

// FLAGGED: user-supplied redirect target with no CRLF sanitisation
String next = request.getParameter("next");
response.sendRedirect(next); // \r\n in next injects arbitrary response headers

// FLAGGED: addHeader with user-controlled attribute
String callback = (String) request.getAttribute("callbackUrl");
response.addHeader("X-Callback", callback);
```

## Remediation

1. Strip all carriage-return (`\r`) and line-feed (`\n`) characters from any value before it is placed into a response header. Use a utility method or a library such as ESAPI's `encodeForHTTP`.
2. For redirect targets, validate the URL against an allowlist of permitted destinations rather than accepting arbitrary user input.
3. Use a framework-level sanitisation layer (e.g., a servlet filter) so that all header-setting code benefits from centralised protection.
4. Upgrade to a modern framework version — recent versions of Spring MVC and Tomcat reject header values containing CRLF sequences by default.

```java
// SAFE: CRLF characters stripped before header is set
private static String sanitiseHeaderValue(String value) {
    if (value == null) return "";
    return value.replaceAll("[\r\n]", "");
}

// SAFE: strip CRLF before setting the header
String lang = sanitiseHeaderValue(request.getParameter("lang"));
response.setHeader("Content-Language", lang);

// SAFE: validate redirect URL against an allowlist
String next = request.getParameter("next");
Set<String> allowed = Set.of("/dashboard", "/profile", "/home");
response.sendRedirect(allowed.contains(next) ? next : "/home");
```

## References

- [CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers](https://cwe.mitre.org/data/definitions/113.html)
- [CAPEC-34: HTTP Response Splitting](https://capec.mitre.org/data/definitions/34.html)
- [OWASP HTTP Response Splitting](https://owasp.org/www-community/attacks/HTTP_Response_Splitting)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [OWASP Java Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Java_Security_Cheat_Sheet.html)
- [OWASP ESAPI: encodeForHTTP](https://owasp.org/www-project-enterprise-security-api/)
