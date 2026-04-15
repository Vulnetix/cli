---
title: "VNX-JAVA-010 – Spring CSRF Protection Disabled"
description: "Detects Spring Security configurations that call csrf().disable() or use equivalent patterns to turn off Cross-Site Request Forgery protection, exposing authenticated users to state-change attacks."
---

## Overview

This rule detects Spring Security configuration code that explicitly disables CSRF (Cross-Site Request Forgery) protection through any of the supported API forms: `csrf().disable()`, `csrf(csrf -> csrf.disable())`, `csrf(AbstractHttpConfigurer::disable)`, `.csrf().ignoringAntMatchers(...)`, or the shorthand `csrf.disable()`. Disabling CSRF protection removes the token check that prevents malicious websites from submitting state-changing requests on behalf of authenticated users. This is CWE-352.

**Severity:** Medium | **CWE:** [CWE-352 – Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)

## Why This Matters

A CSRF attack works by inducing an authenticated user's browser to send a request to your application. Because browsers automatically include cookies with cross-origin requests, a session cookie present in the browser is sent along with the forged request. Without a CSRF token — a unique, unpredictable value tied to the user's session that a cross-origin attacker cannot read — your server has no way to distinguish a legitimate form submission from a forged one.

Practical consequences include account takeover (an attacker can change a victim's email address or password), financial fraud (trigger a funds transfer or purchase), privilege escalation (promote an account to admin), and data destruction (delete records). CSRF is particularly dangerous in banking applications, admin dashboards, and SaaS tools where authenticated actions have high business impact.

`csrf().disable()` is commonly added during development to simplify API testing with `curl` or Postman, and is sometimes cargo-culted into stateless REST APIs on the assumption that they are not vulnerable. Stateless APIs that use cookie-based session authentication are vulnerable. Stateless APIs using `Authorization: Bearer` headers with JWTs are generally safe, as browsers do not automatically attach custom headers to cross-origin requests — but the Spring configuration should reflect the actual authentication mechanism.

## What Gets Flagged

Any `.java` file containing one of the CSRF disable patterns.

```java
// FLAGGED: legacy Spring Security API
http.csrf().disable();

// FLAGGED: lambda DSL form
http.csrf(csrf -> csrf.disable());

// FLAGGED: method reference form
http.csrf(AbstractHttpConfigurer::disable);

// FLAGGED: partially disabled (still creates a vulnerability surface)
http.csrf().ignoringAntMatchers("/api/**");
```

## Remediation

1. **Remove the `csrf().disable()` call entirely.** Spring Security enables CSRF protection by default. Simply removing the disable call restores it. For form-based authentication, use Spring's `CsrfTokenRepository` (defaulting to `HttpSessionCsrfTokenRepository`) and include the `_csrf` token in all HTML forms using Thymeleaf's `th:action`, JSP's `<sec:csrfInput/>`, or a hidden field populated from the session.

   ```java
   // SAFE: CSRF enabled (default) with explicit repository configuration
   @Bean
   public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
       http
           .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
           .formLogin(Customizer.withDefaults())
           .csrf(csrf -> csrf
               .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
           );
       return http.build();
   }
   ```

2. **For SPAs and AJAX-heavy applications, use `CookieCsrfTokenRepository`.** This stores the CSRF token in a cookie readable by JavaScript (`XSRF-TOKEN`) while requiring it to be echoed back as an HTTP header (`X-XSRF-TOKEN`). Angular's `HttpClient` and Axios both support this pattern out of the box.

   ```java
   // SAFE: cookie-based CSRF token for Angular/React SPA
   http.csrf(csrf -> csrf
       .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
   );
   ```

   ```javascript
   // Angular reads XSRF-TOKEN cookie and sends X-XSRF-TOKEN header automatically
   // No additional configuration needed in Angular's HttpClientModule
   ```

3. **For pure stateless REST APIs using Bearer token authentication, explicitly document the decision.** If your API genuinely authenticates solely via `Authorization: Bearer` headers (not cookies), CSRF is not applicable. Leave a clear code comment explaining this rather than simply calling `disable()` without context:

   ```java
   // SAFE: stateless JWT API — CSRF not applicable because no cookie authentication is used
   http
       .sessionManagement(session ->
           session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
       .csrf(csrf -> csrf.disable())  // safe: bearer token auth only, no session cookies
       .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
   ```

4. **Add integration tests that verify CSRF protection is active.** Use Spring's `MockMvc` with `SecurityMockMvcRequestPostProcessors.csrf()` removed to assert that POST endpoints return 403 without a valid token.

## References

- [CWE-352: Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)
- [CAPEC-62: Cross-Site Request Forgery](https://capec.mitre.org/data/definitions/62.html)
- [MITRE ATT&CK T1189 – Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
- [OWASP Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Spring Security – CSRF Protection](https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html)
- [OWASP Top 10 A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP ASVS V4 – Access Control](https://owasp.org/www-project-application-security-verification-standard/)
