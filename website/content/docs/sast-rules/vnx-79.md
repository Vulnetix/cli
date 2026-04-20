---
title: "VNX-79 – Cross-Site Scripting (XSS)"
description: "Detect unescaped user-controlled data rendered in HTML contexts across JavaScript/React, PHP, Python/Django, Ruby/Rails, and Java."
---

## Overview

This rule flags patterns where user-supplied data is written into an HTML response or DOM without HTML-encoding. Cross-site scripting (XSS) allows an attacker to inject malicious JavaScript into a page that is then executed in the browsers of other users. The consequences range from session-cookie theft and account takeover to keylogging, phishing overlays, malware distribution, and defacement. This maps to [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html).

**Severity:** High | **CWE:** [CWE-79 – Cross-Site Scripting](https://cwe.mitre.org/data/definitions/79.html)

## Why This Matters

XSS has appeared in the OWASP Top Ten every year since the list was first published. It affects every language and framework that generates HTML, and the impact of stored XSS in particular is severe: a single injected script can silently compromise every user who visits a page. Modern frameworks like React and Django auto-escape by default, but developers routinely bypass those protections — `dangerouslySetInnerHTML`, `mark_safe()`, `.html_safe`, `raw()` — without realising the implications. The rule targets these bypass mechanisms specifically, where the security-conscious decision has already been made to escape the framework's built-in protection.

## What Gets Flagged

```jsx
// FLAGGED: React dangerouslySetInnerHTML with user data
function Comment({ text }) {
    return <div dangerouslySetInnerHTML={{ __html: text }} />;
    // If text comes from user input, this is XSS
}
```

```javascript
// FLAGGED: direct innerHTML assignment
document.getElementById('output').innerHTML = req.query.message;
```

```javascript
// FLAGGED: document.write with user input
document.write('<p>' + location.hash.slice(1) + '</p>');
```

```php
<?php
// FLAGGED: direct echo of superglobal
echo $_GET['name'];         // attacker sends: <script>alert(1)</script>
echo $_POST['comment'];
```

```python
# FLAGGED: Django mark_safe with user input
from django.utils.safestring import mark_safe

def view(request):
    name = request.GET['name']
    return HttpResponse(mark_safe('<h1>' + name + '</h1>'))  # bypasses auto-escaping
```

```ruby
# FLAGGED: html_safe on user input
def show
    @output = params[:message].html_safe  # disables Rail's auto-escaping
end
```

```java
// FLAGGED: response writer with request parameter
String name = request.getParameter("name");
response.getWriter().println("<p>Hello " + name + "</p>");
```

## Remediation

1. **Let the framework escape output by default.** React's JSX, Django templates, Rails ERB, and Jinja2 all escape HTML automatically when you use their standard rendering mechanisms.

```jsx
// SAFE: React — pass text as a prop, not as HTML
function Comment({ text }) {
    return <div>{text}</div>;  // React escapes this automatically
}
```

```python
# SAFE: Django template (auto-escaping is on by default)
# In template: {{ name }} — escapes automatically
# Or in view:
from django.utils.html import format_html
return HttpResponse(format_html('<h1>{}</h1>', name))
```

```ruby
# SAFE: Rails ERB auto-escapes by default
# In view: <%= @message %>   — escapes automatically
# In controller:
@message = params[:message]   # no .html_safe
```

2. **Use a trusted HTML sanitiser when you genuinely need to render rich HTML.** Libraries like DOMPurify (JavaScript), bleach (Python), and Loofah (Ruby) strip dangerous tags and attributes while preserving legitimate markup.

```javascript
// SAFE: DOMPurify sanitises before insertion
import DOMPurify from 'dompurify';

function Comment({ html }) {
    const clean = DOMPurify.sanitize(html);
    return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}
```

```php
<?php
// SAFE: htmlspecialchars encodes HTML entities
echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
```

```java
// SAFE: OWASP Java Encoder
import org.owasp.encoder.Encode;

response.getWriter().println("<p>Hello " + Encode.forHtml(name) + "</p>");
```

3. **Set a strict Content Security Policy (CSP).** CSP is a defence-in-depth control that restricts which scripts can execute even if an XSS payload is injected.

4. **Use `HttpOnly` and `Secure` cookie flags.** Even if XSS occurs, `HttpOnly` prevents JavaScript from reading the session cookie, limiting the attacker's ability to hijack sessions.

## References

- [CWE-79: Cross-Site Scripting](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP DOM-Based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [DOMPurify — trusted HTML sanitiser for the browser](https://github.com/cure53/DOMPurify)
- [OWASP Java Encoder](https://owasp.org/www-project-java-encoder/)
- [CAPEC-86: XSS via HTTP Query Strings](https://capec.mitre.org/data/definitions/86.html)
- [MITRE ATT&CK T1059.007 – JavaScript](https://attack.mitre.org/techniques/T1059/007/)
