---
title: "VNX-NODE-005 – innerHTML or dangerouslySetInnerHTML Usage"
description: "Reports HTML written into the DOM of a JavaScript or TypeScript file from a non-constant value (insertAdjacentHTML, document.write, React dangerouslySetInnerHTML) that is not sanitized. innerHTML/outerHTML assignments are reported by VNX-NODE-027."
---

## Overview

This rule flags `insertAdjacentHTML()`, `document.write()`/`writeln()` and React's `dangerouslySetInnerHTML` prop in JavaScript and TypeScript source files. An assignment to `.innerHTML` or `.outerHTML` is the same weakness and is reported by [VNX-NODE-027](../vnx-node-027/), so one sink is never shown twice; the same sinks in HTML pages and Vue or Svelte components are [VNX-NODE-012](../vnx-node-012/)'s. These mechanisms inject raw HTML directly into the DOM. When the injected content includes any user-controlled data — from a database record, URL parameter, API response, or user profile field — an attacker can embed `<script>` tags or event handler attributes that execute arbitrary JavaScript in other users' browsers. This is CWE-79 (Improper Neutralization of Input During Web Page Generation — Cross-site Scripting).

**Severity:** Medium | **CWE:** [CWE-79 – Improper Neutralization of Input During Web Page Generation (XSS)](https://cwe.mitre.org/data/definitions/79.html)

## Why This Matters

Stored XSS via innerHTML is one of the most common and impactful web vulnerabilities. An attacker who finds a stored-XSS path can inject a payload that silently executes every time another user loads the page. Typical payloads steal session cookies, exfiltrate CSRF tokens, hijack form submissions to forward credentials to an attacker-controlled server, or inject a keylogger. In admin panels, a single stored-XSS finding can lead to account takeover for every administrator who views the compromised content.

React specifically named its prop `dangerouslySetInnerHTML` to make developers pause — but the warning is easy to ignore under deadline pressure, and the property is frequently used to render rich text from a CMS or user-generated HTML. The danger is identical to vanilla `innerHTML`: if the content has not been sanitised through a dedicated HTML sanitisation library, the application is vulnerable.

## What Gets Flagged

```javascript
// FLAGGED: template literal / concatenation
container.insertAdjacentHTML('beforeend', `<div>${message}</div>`);
document.write("<a href='" + ref + "'>back</a>");

// FLAGGED: one part encoded, the raw value spliced into another
document.write('<a href="/s?q=' + encodeURIComponent(q) + '">' + q + '</a>');

// FLAGGED: React prop, also when split over lines
<div dangerouslySetInnerHTML={{ __html: body }} />

// NOT FLAGGED here: reported by VNX-NODE-027
el.innerHTML = `<h2>${user.name}</h2>`;
node["innerHTML"] = msg;
```

Not flagged: string literals without interpolation, `null`, number and boolean literals, ALL_CAPS constants (`SPINNER_SVG`), values passed whole through `DOMPurify.sanitize`, `sanitize-html` or an escape/encode helper (`unescape()` decodes and is not one), `textContent`/`innerText`, comments and strings, minified and vendored files (`vendor/`, `libs/`, `plugins/`, `jquery*.js`).

## Remediation

1. **Use `textContent` instead of `innerHTML` when you only need to display plain text.** `textContent` sets the text node value and never parses HTML, completely eliminating the XSS vector:

   ```javascript
   // SAFE: textContent does not parse HTML
   document.getElementById('preview').textContent = userInput;
   ```

2. **If you must render rich HTML, sanitize it with DOMPurify before assignment.** DOMPurify parses the HTML in a sandboxed environment and strips all dangerous elements and attributes:

   ```javascript
   // SAFE: DOMPurify sanitizes before innerHTML assignment
   import DOMPurify from 'dompurify';

   document.getElementById('preview').innerHTML = DOMPurify.sanitize(userInput);
   ```

3. **In React, sanitize before passing to `dangerouslySetInnerHTML`:**

   ```javascript
   // SAFE: sanitize rich text before rendering
   import DOMPurify from 'dompurify';

   function Comment({ text }) {
     const clean = DOMPurify.sanitize(text);
     return <div dangerouslySetInnerHTML={{ __html: clean }} />;
   }
   ```

4. **Use React's default JSX rendering for user-supplied text.** React's JSX template syntax (`{variable}`) escapes HTML entities automatically — use it wherever you only need to display text, not render markup:

   ```javascript
   // SAFE: JSX escapes HTML entities by default
   function Comment({ text }) {
     return <div>{text}</div>;
   }
   ```

5. **Install and configure DOMPurify:**

   ```bash
   npm install dompurify
   # For TypeScript:
   npm install --save-dev @types/dompurify
   ```

6. **Set a Content Security Policy** that restricts inline scripts (`script-src 'self'`) as a defence-in-depth measure. A strong CSP prevents injected `<script>` tags from executing even if sanitisation is bypassed or absent.

## References

- [CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)](https://cwe.mitre.org/data/definitions/79.html)
- [DOMPurify – npm package and documentation](https://github.com/cure53/DOMPurify)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [React – dangerouslySetInnerHTML documentation](https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html)
- [MDN – Element.innerHTML security considerations](https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML#security_considerations)
