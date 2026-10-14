---
title: "VNX-JAVA-027 – Java Spring Security Headers Disabled"
description: "Detects Spring Security configurations that disable all default security headers, X-Frame-Options, HSTS or X-Content-Type-Options, in the chained, lambda and method-reference DSL forms. xssProtection().disable(), sameOrigin()/deny() and test code are not reported."
---

## Overview

Spring Security automatically adds a set of defensive HTTP response headers — `X-Frame-Options`, `X-Content-Type-Options`, `X-XSS-Protection`, `Strict-Transport-Security`, and `Content-Security-Policy` — when the `headers()` configuration is active (the default). Calling `frameOptions().disable()` disables the `X-Frame-Options` header specifically, while calling `headers().disable()` removes all security headers entirely. Both patterns leave the application exposed to clickjacking and related UI-redressing attacks. This is captured by CWE-693 (Protection Mechanism Failure).

This rule flags `headers().disable()`, `frameOptions().disable()`, `httpStrictTransportSecurity().disable()` and `contentTypeOptions().disable()` in every form the Spring Security DSL accepts: the chained form (also when `.headers()`, `.frameOptions()` and `.disable()` sit on separate lines), the lambda form (`headers(h -> h.disable())`, `frameOptions(f -> { f.disable(); })`) and the method-reference form (`headers(AbstractHttpConfigurer::disable)`, `frameOptions(FrameOptionsConfig::disable)`). It does not report `xssProtection().disable()` (the X-XSS-Protection header is deprecated and disabling it is current advice), `csrf()`/`cors()` disable calls, `sameOrigin()`/`deny()`, test code, comments or string literals.

The `X-Frame-Options` header is the primary defence against clickjacking: it prevents the application from being embedded in an `<iframe>` on a third-party page. Without it, an attacker can overlay an invisible iframe of the legitimate application over a deceptive page, tricking users into performing authenticated actions (transferring funds, changing account settings, approving access) without their knowledge.

**Severity:** Medium | **CWE:** [CWE-693 – Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)

## Why This Matters

Clickjacking attacks are difficult for users to detect because the malicious page looks entirely legitimate — the attacker's visible UI element is placed precisely over a hidden, transparent iframe of the target application. The user interacts with what appears to be a harmless button or link but is actually submitting an authenticated request to the target application.

When `headers().disable()` is used, the application also loses `Strict-Transport-Security` (HSTS) and `X-Content-Type-Options`. Without HSTS, an active network attacker can downgrade HTTPS to HTTP on the user's first visit. Without `X-Content-Type-Options: nosniff`, MIME-type sniffing attacks become possible in older browsers.

Spring Security's default header configuration is safe and suitable for most applications. The `headers().disable()` call is most often introduced by developers following outdated tutorials or copying configurations from non-security-sensitive internal tools. The fix is always to restore the default or configure the headers explicitly rather than disable them.

## What Gets Flagged

```java
// FLAGGED: X-Frame-Options explicitly disabled
http
    .headers()
        .frameOptions().disable()
    ...

// FLAGGED: all HTTP security headers disabled
http
    .headers().disable()
    ...

// FLAGGED: lambda and method-reference DSL
.headers(headers -> headers.disable())
.headers(h -> h.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
.httpStrictTransportSecurity(hsts -> hsts.disable())
```

## Remediation

1. **Remove `frameOptions().disable()`** and replace it with `frameOptions().deny()` (prevents all framing) or `frameOptions().sameOrigin()` (allows framing only from the same origin).

2. **Remove `headers().disable()`** entirely. Spring Security's default header set is appropriate for production use in virtually all applications.

3. **If embedding in a specific partner domain is required**, configure a Content-Security-Policy `frame-ancestors` directive rather than disabling `X-Frame-Options`.

```java
// SAFE: explicit header configuration using Spring Security 6 lambda DSL
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .headers(headers -> headers
            .frameOptions(frame -> frame.deny())
            .contentSecurityPolicy(csp -> csp
                .policyDirectives("default-src 'self'; frame-ancestors 'none'"))
            .httpStrictTransportSecurity(hsts -> hsts
                .includeSubDomains(true)
                .maxAgeInSeconds(31536000))
        )
        // ... rest of configuration
    ;
    return http.build();
}
```

```java
// SAFE: allowing same-origin framing (e.g. for a dashboard with iframes)
http
    .headers(headers -> headers
        .frameOptions(frame -> frame.sameOrigin())
    );
```

## References

- [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)
- [OWASP Clickjacking Defence Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)
- [Spring Security Reference – HTTP Security Headers](https://docs.spring.io/spring-security/reference/servlet/exploits/headers.html)
- [MDN: X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)
- [CAPEC-103: Clickjacking](https://capec.mitre.org/data/definitions/103.html)
