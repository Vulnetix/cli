---
title: "VNX-NODE-012 – Client-Side XSS via innerHTML or v-html"
description: "Detects client-side XSS sinks including innerHTML, outerHTML, document.write, jQuery .html(), and Vue v-html that inject raw HTML from dynamic content."
---

## Overview

This rule detects a broader set of DOM-based XSS sinks beyond React's `dangerouslySetInnerHTML`: `.innerHTML =`, `.outerHTML =`, `document.write()`, `document.writeln()`, Vue's `v-html` directive, and jQuery's `.html()` method. All of these inject raw HTML into the live DOM. When the content is dynamic — fetched from an API, derived from URL parameters, read from `localStorage`, or received from a WebSocket — an attacker who can influence that content can inject `<script>` tags or inline event handlers that execute in the victim's browser. This is CWE-79 (Improper Neutralization of Input During Web Page Generation — Cross-site Scripting).

**Severity:** High | **CWE:** [CWE-79 – Improper Neutralization of Input During Web Page Generation (XSS)](https://cwe.mitre.org/data/definitions/79.html)

## Why This Matters

DOM-based XSS is particularly subtle because the malicious payload never reaches the server — it exists entirely in the client-side code path and may not be detected by server-side WAFs or input validation. An attacker can craft a URL with a fragment or query parameter that a JavaScript-heavy application reads and injects into the DOM. The payload steals session cookies, reads `localStorage` tokens, silently submits forms, or injects persistent content into the page.

`document.write()` is especially dangerous because it can completely replace the page content after load, and its usage in modern applications is almost always a legacy anti-pattern. Vue's `v-html` is the framework-specific equivalent of `innerHTML` — it bypasses Vue's built-in template XSS protections and must only be used with pre-sanitized content.

## What Gets Flagged

The rule matches any line containing `.innerHTML =`, `.innerHTML=`, `.outerHTML =`, `.outerHTML=`, `document.write(`, `document.writeln(`, `v-html=`, `dangerouslySetInnerHTML`, or the jQuery pattern `$(...).html(`.

```javascript
// FLAGGED: innerHTML from API response
fetch('/api/user-bio').then(r => r.text()).then(bio => {
  document.getElementById('bio').innerHTML = bio;
});

// FLAGGED: document.write with dynamic content
document.write('<div>' + location.hash.substring(1) + '</div>');

// FLAGGED: jQuery .html() with dynamic value
$('#notification').html(apiResponse.message);
```

```html
<!-- FLAGGED: Vue v-html with dynamic data -->
<div v-html="userBio"></div>
```

## Remediation

1. **Replace `.innerHTML` with `.textContent` for plain text content.** This is the most common safe fix — `textContent` sets the text node value without parsing HTML:

   ```javascript
   // SAFE: textContent does not parse HTML
   document.getElementById('bio').textContent = bio;
   ```

2. **Use framework-native safe bindings instead of raw HTML injection.** In Vue, use `{{ variable }}` template syntax (which HTML-escapes automatically) instead of `v-html`:

   ```html
   <!-- SAFE: Vue double-curly escapes HTML automatically -->
   <div>{{ userBio }}</div>

   <!-- SAFE: only use v-html with pre-sanitized content -->
   <div v-html="sanitizedBio"></div>
   ```

3. **Sanitize with DOMPurify when HTML rendering is genuinely required:**

   ```javascript
   // SAFE: DOMPurify strips dangerous elements and attributes
   import DOMPurify from 'dompurify';

   document.getElementById('content').innerHTML = DOMPurify.sanitize(richText);

   // In Vue with v-html:
   computed: {
     sanitizedBio() {
       return DOMPurify.sanitize(this.userBio);
     }
   }
   ```

4. **Replace jQuery `.html()` with `.text()` for text content, or sanitize before `.html()`:**

   ```javascript
   // SAFE: jQuery .text() escapes HTML
   $('#notification').text(apiResponse.message);

   // SAFE: sanitize before .html() if markup is needed
   $('#content').html(DOMPurify.sanitize(apiResponse.html));
   ```

5. **Eliminate `document.write()` entirely.** There is no safe modern use of `document.write()`. Replace it with `document.createElement()` and `textContent`, or manipulate the DOM directly after page load.

6. **Set a Content Security Policy** header that disallows `'unsafe-inline'` scripts and restricts script sources. This is defence-in-depth that limits injection impact even when a sink is present.

## References

- [CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)](https://cwe.mitre.org/data/definitions/79.html)
- [DOMPurify – trusted HTML sanitization](https://github.com/cure53/DOMPurify)
- [OWASP DOM-Based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [Vue.js – v-html security warning](https://vuejs.org/api/built-in-directives.html#v-html)
- [jQuery – .html() security](https://api.jquery.com/html/)
- [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [MITRE ATT&CK T1059.007 – JavaScript](https://attack.mitre.org/techniques/T1059/007/)
