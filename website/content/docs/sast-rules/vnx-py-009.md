---
title: "VNX-PY-009 – Jinja2 Autoescape Disabled"
description: "Detect Jinja2 Environment instances created with autoescape=False, which renders user-supplied template variables without HTML escaping and enables cross-site scripting."
---

## Overview

This rule flags `jinja2.Environment()` calls that explicitly set `autoescape=False`. When Jinja2's autoescape is disabled, any string value rendered into a template is inserted verbatim into the HTML output. If that value contains HTML or JavaScript (from user input, a database field, or an API response), the browser will execute it as code rather than display it as text — a classic reflected or stored cross-site scripting (XSS) vulnerability. This maps to [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html).

**Severity:** High | **CWE:** [CWE-79 – Cross-Site Scripting (XSS)](https://cwe.mitre.org/data/definitions/79.html)

## Why This Matters

XSS in a web application allows an attacker to execute JavaScript in the victim's browser in the context of the target origin. The consequences depend on the application's functionality but typically include session token theft (leading to account takeover), keylogging, UI redirection, form hijacking, and in applications with high privileges (admin panels, financial dashboards), the ability to perform any action the victim user can perform.

Stored XSS is particularly damaging: a single injection that writes to a database can affect every user who views the contaminated content. A user comment field, a product description, a username — any of these stored with autoescape disabled can become a persistent attack vector.

Jinja2's `autoescape=False` is the default in older versions, and many code examples from documentation and tutorials were written before autoescape became the recommended default. This means legacy codebases often have autoescape disabled throughout, not just in isolated places.

## What Gets Flagged

Any line where `Environment(` is called with `autoescape=False`.

```python
# FLAGGED: autoescape explicitly disabled
env = Environment(autoescape=False)

# FLAGGED: autoescape=False with other arguments
env = Environment(
    loader=FileSystemLoader("templates"),
    autoescape=False,
)

# FLAGGED: creating env in a factory function
def make_env():
    return Environment(loader=PackageLoader("myapp"), autoescape=False)
```

## Remediation

1. **Enable autoescape unconditionally with `autoescape=True`.** This escapes `&`, `<`, `>`, `"`, and `'` in all rendered string variables for every template rendered by this environment:

```python
from jinja2 import Environment, FileSystemLoader

# SAFE: autoescape=True escapes all string values by default
env = Environment(
    loader=FileSystemLoader("templates"),
    autoescape=True,
)
```

2. **Use `select_autoescape()` for context-aware escaping.** This enables autoescape for HTML and XML templates while leaving it disabled for text/plain and other non-HTML formats where HTML escaping would be wrong (e.g., Markdown rendering, email text):

```python
from jinja2 import Environment, FileSystemLoader, select_autoescape

# SAFE: autoescapes HTML and XML templates, not .txt or .md
env = Environment(
    loader=FileSystemLoader("templates"),
    autoescape=select_autoescape(["html", "xml"]),
)
```

3. **Mark trusted HTML content explicitly with `Markup`.** If you have values that are intentionally HTML (e.g., pre-sanitised rich text) and should not be escaped, wrap them in `jinja2.Markup` (or `markupsafe.Markup`) explicitly. This makes your intent auditable:

```python
from markupsafe import Markup

# Pre-sanitised HTML content
safe_html = sanitize_html(user_rich_text)  # using bleach or similar
template_vars["content"] = Markup(safe_html)
```

4. **Use Flask's `render_template` instead of `render_template_string`.** Flask configures its Jinja2 environment with autoescape enabled for HTML templates by default. Using static template files rather than inline template strings both enables autoescape and reduces SSTI risk:

```python
from flask import render_template

# SAFE: Flask's default environment has autoescape enabled for .html
@app.route("/profile")
def profile():
    return render_template("profile.html", username=current_user.name)
```

5. **Audit existing templates for `| safe` filter usage.** Even with autoescape enabled, the `| safe` filter marks a value as trusted HTML and skips escaping. Audit every `| safe` occurrence to confirm the value is genuinely safe.

## References

- [CWE-79: Cross-Site Scripting (XSS)](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [Jinja2 documentation – Autoescaping](https://jinja.palletsprojects.com/en/stable/api/#autoescaping)
- [Flask documentation – Jinja2 autoescape](https://flask.palletsprojects.com/en/stable/templating/#jinja-setup)
- [CAPEC-86: XSS Using HTTP Query Strings](https://capec.mitre.org/data/definitions/86.html)
- [MITRE ATT&CK T1059.007 – Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/)
