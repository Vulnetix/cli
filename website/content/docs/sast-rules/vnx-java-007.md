---
title: "VNX-JAVA-007 – Java Open Redirect"
description: "Detects Java servlet and Spring MVC code that passes user-controlled request parameters directly to response.sendRedirect() or ModelAndView redirect, enabling phishing via URL redirection."
---

## Overview

This rule detects patterns where a value read from `request.getParameter()` or `req.getParameter()` is passed directly — without validation — to `response.sendRedirect()`, a Spring `ModelAndView` redirect string, or a `RedirectView` constructor. An open redirect allows an attacker to craft a link that appears to originate from your trusted domain but silently redirects the user to an attacker-controlled site. This is CWE-601.

**Severity:** Medium | **CWE:** [CWE-601 – URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)

## Why This Matters

Open redirects are a reliable tool in phishing campaigns precisely because they abuse the victim's trust in the source domain. An attacker sends a link such as `https://yourapp.example.com/login?next=https://attacker.com/harvest`. The victim sees `yourapp.example.com` in the URL and clicks it. After any authentication flow, the server sends a `302 Location: https://attacker.com/harvest` response and the browser follows it silently. The victim is now on the attacker's page, which may credential-harvest, deliver malware, or redirect again to the real site to avoid suspicion.

Open redirects are also used as an intermediate step in OAuth phishing attacks, where an `open_redirect` on the authorisation server or relying party can be combined with the `redirect_uri` parameter to steal authorisation codes or access tokens. Bug-bounty programmes and security researchers routinely report open redirects, and the presence of one in a login or post-authentication flow raises your overall risk profile.

## What Gets Flagged

The rule matches lines that directly combine a parameter read with a redirect call.

```java
// FLAGGED: user-controlled URL sent directly to sendRedirect
String next = request.getParameter("next");
response.sendRedirect(next);

// FLAGGED: Spring MVC redirect with user-controlled string
String target = request.getParameter("url");
return new ModelAndView("redirect:" + target);

// FLAGGED: RedirectView with user-supplied parameter
String dest = request.getParameter("destination");
return new RedirectView(request.getParameter("destination"));
```

## Remediation

1. **Validate the redirect target against an allowlist of permitted destinations.** The safest approach is to not accept an arbitrary URL at all — instead accept a short token or named destination that maps to a known URL.

   ```java
   // SAFE: token-based redirect — user never controls the URL directly
   private static final Map<String, String> ALLOWED_REDIRECTS = Map.of(
       "dashboard", "/app/dashboard",
       "profile",   "/app/profile",
       "home",      "/"
   );

   String token = request.getParameter("next");
   String destination = ALLOWED_REDIRECTS.getOrDefault(token, "/");
   response.sendRedirect(destination);
   ```

2. **If you must accept arbitrary URLs, validate that the destination belongs to your own domain.** Parse the URL, extract the host, and compare it to a set of trusted hostnames. Reject anything that does not match, including encoded forms like `%2F` and protocol-relative URLs like `//attacker.com`.

   ```java
   // SAFE: host allowlist validation before redirect
   String rawUrl = request.getParameter("next");
   try {
       URI uri = new URI(rawUrl).normalize();
       String host = uri.getHost();
       Set<String> allowedHosts = Set.of("example.com", "www.example.com");
       if (host != null && allowedHosts.contains(host.toLowerCase())) {
           response.sendRedirect(rawUrl);
       } else {
           response.sendRedirect("/");  // fall back to safe default
       }
   } catch (URISyntaxException e) {
       response.sendRedirect("/");
   }
   ```

3. **Prefer relative URLs for post-login redirects.** If the redirect target is always within your own application, accept only path-relative URLs (starting with `/`) and reject any value containing `://` or starting with `//`.

   ```java
   // SAFE: only relative paths accepted
   String next = request.getParameter("next");
   if (next != null && next.startsWith("/") && !next.startsWith("//")) {
       response.sendRedirect(next);
   } else {
       response.sendRedirect("/home");
   }
   ```

4. **Use Spring Security's `SavedRequestAwareAuthenticationSuccessHandler`.** For post-login redirects in Spring Security applications, delegate to this handler rather than reading and forwarding a `next` parameter yourself. It uses its own URL validation before redirecting.

## References

- [CWE-601: URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html)
- [CAPEC-194: Fake the Source of Data](https://capec.mitre.org/data/definitions/194.html)
- [MITRE ATT&CK T1566 – Phishing](https://attack.mitre.org/techniques/T1566/)
- [OWASP Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [OWASP Top 10 A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP ASVS V5 – Validation, Sanitization and Encoding](https://owasp.org/www-project-application-security-verification-standard/)
