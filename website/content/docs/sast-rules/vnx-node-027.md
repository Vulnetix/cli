---
title: "VNX-NODE-027 – Assignment to innerHTML without sanitization"
description: "Detects direct assignment to .innerHTML in JavaScript files, which can introduce DOM-based XSS when the assigned value originates from user-controlled input."
---

## Overview

This rule detects direct assignment to the `.innerHTML` property in JavaScript files. Setting `innerHTML` to a value that incorporates user-controlled data causes the browser to parse the string as HTML, executing any embedded script tags, event handlers (`onerror`, `onload`, etc.), or JavaScript URLs (`javascript:`). This is classified as CWE-79 (Improper Neutralization of Input During Web Page Generation) and is one of the most common sources of DOM-based XSS in modern web applications.

Unlike reflected or stored XSS that originates on the server, DOM-based XSS from `innerHTML` assignment occurs entirely in the browser. The payload never passes through the server, making it invisible to server-side input validation and many web application firewalls. The vulnerability is triggered when client-side JavaScript reads attacker-controlled data — from the URL fragment, `location.search`, `document.referrer`, `postMessage` events, or local storage — and writes it into the DOM via `innerHTML`.

**Severity:** High | **CWE:** [CWE-79 – Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html) | **OWASP:** [A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/) | **CAPEC:** [CAPEC-63 – Cross-Site Scripting (XSS)](https://capec.mitre.org/data/definitions/63.html) | **ATT&CK:** [T1059.007](https://attack.mitre.org/techniques/T1059/007/)

## Why This Matters

DOM XSS is actively exploited in the wild and is frequently discovered in widely-used JavaScript libraries and single-page applications. An attacker who achieves script execution in a victim's browser can steal session cookies, capture keystrokes, redirect to phishing pages, make authenticated API requests, or exfiltrate data from the page. Modern browsers have removed synchronous `<script>` execution via `innerHTML` but remain vulnerable to event handler injection (`<img onerror="...">`), which is sufficient for full script execution.

In Node.js SSR (server-side rendering) contexts — for example, React/Vue/Angular applications with Express back-ends that pass props via `dangerouslySetInnerHTML` or equivalent — the same sink can produce reflected XSS that is indexed by search engines and easily shared as a malicious link.

## What Gets Flagged

```javascript
// FLAGGED: user input from URL assigned directly to innerHTML
const name = new URLSearchParams(location.search).get('name');
document.getElementById('greeting').innerHTML = 'Hello, ' + name;

// FLAGGED: server-provided data injected into DOM without sanitization
element.innerHTML = apiResponse.htmlContent;

// FLAGGED: template string with user data
container.innerHTML = `<p>${req.body.comment}</p>`;
```

## Remediation

1. Use `textContent` instead of `innerHTML` when inserting plain text — it is never interpreted as HTML and requires no sanitization.
2. When HTML structure must be inserted dynamically, sanitize the input with [DOMPurify](https://github.com/cure53/DOMPurify) before assigning it to `innerHTML`. Configure DOMPurify with a strict allowlist appropriate to your use case.
3. Use DOM construction APIs (`document.createElement`, `element.appendChild`, `element.setAttribute`) to build HTML programmatically rather than via string parsing.
4. In frameworks like React, avoid `dangerouslySetInnerHTML`; if unavoidable, pass the value through DOMPurify first.

```javascript
// SAFE: textContent for plain text — never parsed as HTML
const name = new URLSearchParams(location.search).get('name');
document.getElementById('greeting').textContent = 'Hello, ' + name;

// SAFE: DOMPurify sanitization before innerHTML assignment
import DOMPurify from 'dompurify';

const clean = DOMPurify.sanitize(apiResponse.htmlContent, {
  ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'],
  ALLOWED_ATTR: ['href'],
});
element.innerHTML = clean;

// SAFE: DOM API construction — no HTML parsing
const p = document.createElement('p');
p.textContent = userComment;
container.appendChild(p);
```

## References

- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [CAPEC-63: Cross-Site Scripting (XSS)](https://capec.mitre.org/data/definitions/63.html)
- [OWASP DOM-based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [DOMPurify — trusted HTML sanitizer](https://github.com/cure53/DOMPurify)
- [MDN Web Docs — innerHTML security considerations](https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML#security_considerations)
- [PortSwigger Web Security Academy — DOM-based XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based)
