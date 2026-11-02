---
title: "VNX-NODE-032 – Angular DomSanitizer bypass with a non-constant value"
description: "Reports bypassSecurityTrustHtml, Style, Script, Url and ResourceUrl calls whose argument is not a constant, since Angular stops sanitising the value and user data becomes cross-site scripting."
---

## Overview

This rule detects calls to the Angular `DomSanitizer` methods `bypassSecurityTrustHtml`, `bypassSecurityTrustStyle`, `bypassSecurityTrustScript`, `bypassSecurityTrustUrl` and `bypassSecurityTrustResourceUrl` when the argument is not a constant. These methods mark a value as safe, so Angular binds it into the page without sanitising it. When the value carries data from a query parameter, an API response or a database row, it is a cross-site scripting hole (CWE-79). The argument may start on the line after the opening parenthesis.

**Severity:** High | **CWE:** [CWE-79 – Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html) | **OWASP:** [A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/) | **CAPEC:** [CAPEC-63 – Cross-Site Scripting (XSS)](https://capec.mitre.org/data/definitions/63.html)

## Why This Matters

Angular escapes and sanitises every template binding by default. The bypass methods turn that off for one value. An attacker who controls the value, for example through a search query that is reflected into the page or a product description stored by another user, runs script in the victim's session. Wrapping the value in a template literal such as `` `<code>${orderId}</code>` `` does not help, because the interpolated data is still unsanitised.

## What Gets Flagged

```typescript
// FLAGGED: query parameter trusted as HTML
this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam)

// FLAGGED: stored data trusted as HTML
tableData[i].description = this.sanitizer.bypassSecurityTrustHtml(tableData[i].description)

// FLAGGED: interpolation inside a template literal
this.orderNo = this.sanitizer.bypassSecurityTrustHtml(`<code>${results.data[0].orderId}</code>`)

// FLAGGED: URL built from a request-controlled value
this.link = this.sanitizer.bypassSecurityTrustUrl(this.route.snapshot.queryParams['next'])
```

Not flagged: a string literal or a template literal without interpolation, an ALL_CAPS constant (`TRUSTED_ICON`, `APP.CDN_URL`), comments, strings that only mention the method, and spec, test and e2e files.

## Remediation

1. Bind the value as text (`{{ value }}`) or through `[innerText]` so Angular escapes it.
2. If rich HTML is required, sanitise it with a vetted library such as DOMPurify and keep the allowed tag list small. Angular's own `DomSanitizer.sanitize(SecurityContext.HTML, value)` is also safe to bind, because it does not bypass.
3. Reserve `bypassSecurityTrust*` for values your own code defines as constants.

```typescript
// SAFE: Angular sanitises the value when it is bound
this.searchValue = this.sanitizer.sanitize(SecurityContext.HTML, queryParam)

// SAFE: constant markup
this.logo = this.sanitizer.bypassSecurityTrustHtml('<b>Shop</b>')
```

## References

- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [Angular security guide: Trusting safe values](https://angular.dev/best-practices/security)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
