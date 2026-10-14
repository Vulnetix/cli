---
title: "VNX-1021 – Improper Restriction of Rendered UI Layers (Clickjacking)"
description: "Reports code and configuration that disables, weakens or removes the browser's frame protection (X-Frame-Options, CSP frame-ancestors, Spring Security, helmet, Django, Rails, Rack, Talisman, ASP.NET), so any site can frame the application."
---

## Overview

VNX-1021 reports [CWE-1021: Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html). The finding is code or configuration that switches off, weakens or removes the browser's frame protection. Once that protection is gone, any site can load the application in an invisible frame and steer the user's clicks (clickjacking).

What is reported:

- **Spring Security**: `frameOptions().disable()` and `headers().disable()`, in their chained, lambda and method-reference forms, including the two-line `.frameOptions()` / `.disable()` chain.
- **X-Frame-Options set to `ALLOWALL`, `ALLOW-FROM` or `ALLOW`**, in Java, JavaScript/TypeScript, Python, PHP, Ruby, Go, C# and `Web.config`. Current browsers ignore `ALLOW-FROM`, so it protects nothing.
- **The header removed** (`removeHeader`, `header_remove`, `del`, `Del`, `Remove`, `delete`, `<remove name=...>`), unless the same file sets a restrictive CSP `frame-ancestors` instead.
- **A CSP `frame-ancestors` directive** whose sources include `*`, `https:` or `http:`.
- **Framework switches**: helmet/lusca `frameguard: false`, `xFrameOptions: false` or `frameguard` action `allow-from`; Django `X_FRAME_OPTIONS` set to anything other than `DENY`/`SAMEORIGIN`, and `@xframe_options_exempt`; Talisman or Rack::Protection `frame_options` set to an allow value; Rack::Protection or Sinatra `protection` with `except: :frame_options`; secure_headers `x_frame_options = OPT_OUT`; Rails `default_headers` emptied or with the header deleted; echo `SecureConfig` `XFrameOptions: ""`; ASP.NET Core `SuppressXFrameOptionsHeader = true`.

Not reported: `DENY` and `SAMEORIGIN` values, `frameOptions().sameOrigin()`/`deny()`, `frame-ancestors` with `'self'`, `'none'` or named hosts, a header removed in a file that sets a restrictive `frame-ancestors`, the absence of any frame protection (other rules judge missing headers), test and spec code, comments and log strings.

**Severity:** Medium | **CWE:** [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html)

## Why This Matters

A clickjacking page loads the target application in a transparent frame on top of something the user wants to click. The user believes they are clicking the attacker's page, but the clicks land on the application, where the user is already signed in: "transfer", "delete account", "grant access" or "enable webcam". Frame protection is the only control that stops this. The browser enforces it only when the response says so, so a single `disable()` or `ALLOWALL` removes it for every page that response covers.

## What Gets Flagged

```java
http.headers().frameOptions().disable();                                     // FLAGGED
http.headers(h -> h.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable));   // FLAGGED
```

```javascript
app.use(helmet({ frameguard: false }));                                      // FLAGGED
res.setHeader('Content-Security-Policy', "default-src 'self'; frame-ancestors *");   // FLAGGED
```

```python
X_FRAME_OPTIONS = 'ALLOWALL'                                                 # FLAGGED

@xframe_options_exempt                                                       # FLAGGED
def widget(request): ...
```

```ruby
use Rack::Protection, except: [:json_csrf, :frame_options]                   # FLAGGED
```

## What Is Not Flagged

```java
http.headers(h -> h.frameOptions(f -> f.sameOrigin()));
response.setHeader("X-Frame-Options", "DENY");
```

```javascript
res.removeHeader('X-Frame-Options');
res.setHeader('Content-Security-Policy', "frame-ancestors 'self' https://partner.example.com");
```

## Remediation

1. Send `X-Frame-Options: DENY`, or `SAMEORIGIN` if the application frames itself.
2. Send `Content-Security-Policy: frame-ancestors 'none'` (or `'self'` and the exact partner origins that may embed the page). This replaces `ALLOW-FROM`.
3. Keep the framework's frame protection on, and exempt only the specific views that must be embedded, with a named `frame-ancestors` list.

## References

- [CWE-1021: Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html)
- [OWASP Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)
- [MDN: CSP frame-ancestors](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors)
