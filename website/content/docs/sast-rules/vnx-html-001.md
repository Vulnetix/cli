---
title: "VNX-HTML-001 – Use of Jinja2 |safe filter"
description: "Detects use of the |safe filter in Jinja2/HTML templates which bypasses auto-escaping and can lead to XSS."
---

## Overview

This rule detects uses of the `|safe` filter in Jinja2 template files (`.html`, `.htm`, `.jinja`, `.jinja2`). Jinja2's auto-escaping mechanism converts characters such as `<`, `>`, `&`, and `"` to their HTML entity equivalents before rendering, preventing injected content from being interpreted as markup. The `|safe` filter tells the engine to skip this escaping entirely, marking the value as pre-sanitized HTML. If the value passed through `|safe` originates from user input or any untrusted source, the result is a reflected or stored Cross-Site Scripting (XSS) vulnerability classified under CWE-79.

XSS via template filters is particularly insidious because the vulnerability lives in the presentation layer rather than the business logic, making it easy to overlook in code review. Developers often apply `|safe` as a shortcut when rendering rich-text content (Markdown output, WYSIWYG editor content, or translated strings) without realizing that any user-controlled segment of that content becomes an injection vector. Even a single unescaped attribute in an otherwise-trusted HTML string can allow script injection.

**Severity:** Medium | **CWE:** [CWE-79 – Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html) | **OWASP:** [A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/)

## Why This Matters

Stored and reflected XSS attacks allow an adversary to execute arbitrary JavaScript in the context of a victim's browser session. This grants access to session cookies (enabling account takeover), the ability to modify page DOM to harvest credentials, access to browser APIs including geolocation and camera, and the ability to make authenticated requests on the victim's behalf. Attacks can propagate virally in user-generated content platforms — a single stored payload may execute for every user who views an infected page.

The `|safe` filter is one of the most common sources of XSS in Python web applications built on Flask and Django. Its misuse has been identified in numerous CVEs affecting open-source projects, CMS platforms, and internal tooling. When combined with markdown-to-HTML rendering, even indirect user influence over the rendered string (via profile fields, comments, or file names) is sufficient to trigger the vulnerability.

## What Gets Flagged

```html
{# FLAGGED: user input rendered without escaping #}
<div class="bio">{{ user.bio | safe }}</div>

{# FLAGGED: untrusted query parameter passed through |safe #}
<p>{{ request.args.get('message') | safe }}</p>

{# FLAGGED: database content marked safe without sanitization #}
<article>{{ post.body | safe }}</article>
```

## Remediation

1. Remove the `|safe` filter and rely on Jinja2's default auto-escaping, which is the secure default when `autoescape=True` is set in the environment.
2. If HTML must be preserved (e.g., rich-text editor output), sanitize the content server-side with `markupsafe.Markup` only after passing it through a trusted HTML sanitizer such as `bleach.clean()` with an explicit allowlist of tags and attributes.
3. Use the `|e` filter explicitly when you want to assert that content is being escaped, making intent clear in templates.
4. Enable `autoescape=True` globally in your Jinja2 environment and never disable it on a per-template basis.

```html
{# SAFE: auto-escaping renders user content harmless #}
<div class="bio">{{ user.bio }}</div>

{# SAFE: server-side sanitization before marking safe #}
{# Python: body = Markup(bleach.clean(post.body, tags=ALLOWED_TAGS)) #}
<article>{{ post.body }}</article>

{# SAFE: use |e to be explicit about escaping intent #}
<p>{{ message | e }}</p>
```

## References

- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [Jinja2 Documentation — HTML Escaping](https://jinja.palletsprojects.com/en/3.1.x/templates/#html-escaping)
- [MarkupSafe — Safe String Handling](https://markupsafe.palletsprojects.com/)
- [bleach — Python HTML Sanitizer](https://bleach.readthedocs.io/)
- [PortSwigger Web Security Academy — Cross-site scripting](https://portswigger.net/web-security/cross-site-scripting)
