---
title: "VNX-PY-012 – Server-Side Template Injection (SSTI)"
description: "Detect Flask and Jinja2 code that passes user-controlled input directly to render_template_string() or Template(), enabling server-side template injection with arbitrary code execution."
---

## Overview

This rule flags Python code that uses `render_template_string()` or `jinja2.Template()` with values derived from user input — specifically f-strings, request attributes, or string concatenation passed as the template argument. Server-side template injection (SSTI) occurs when user input is interpreted as template syntax rather than as data. Because Jinja2 templates can access Python internals, a successful SSTI payload gives an attacker full remote code execution on the server. This maps to [CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine](https://cwe.mitre.org/data/definitions/1336.html).

**Severity:** Critical | **CWE:** [CWE-1336 – Server-Side Template Injection](https://cwe.mitre.org/data/definitions/1336.html) | **Bandit:** B702 (jinja2 autoescape false / template injection)

> **Default behavior:** Flask's `render_template_string()` does NOT sandbox the template expression. Any template syntax in the string is executed with full Jinja2 permissions. Passing user input as the template string — rather than as a context variable — is insecure by design; there is no flag to make it safe.

## Why This Matters

Jinja2 templates execute Python-like expressions inside `{{ }}` and `{% %}` blocks. When user input becomes part of the template string itself (rather than a variable passed to a static template), the attacker can inject template syntax. A classic probe is `{{7*7}}` — if the server responds with `49` instead of the literal string `{{7*7}}`, the endpoint is confirmed vulnerable.

From there, Jinja2's sandbox is weak. An attacker can traverse Python's object hierarchy to reach `os.popen` or `subprocess`:

```
{{ config.items() }}                     # leaks SECRET_KEY and all config
{{ request.application.__globals__ }}   # access Flask's global namespace
{{ ''.__class__.__mro__[1].__subclasses__()[N].__init__.__globals__['os'].popen('id').read() }}
```

Unlike XSS, SSTI does not require a victim user to be present — the attacker exploits the server directly. The impact is full server compromise: arbitrary code execution with the application's privileges, access to all environment variables and secrets, and the ability to read or modify any file the process can reach.

## What Gets Flagged

The rule matches patterns where user input flows directly into `render_template_string` or `Template` as the template itself.

```python
from flask import request, render_template_string

# FLAGGED: f-string with user input as the template
@app.route("/greet")
def greet():
    name = request.args.get("name", "World")
    return render_template_string(f"<h1>Hello {name}!</h1>")
    # Attacker sends: ?name={{config}}  → leaks Flask SECRET_KEY

# FLAGGED: request attribute as the template
@app.route("/preview", methods=["POST"])
def preview():
    return render_template_string(request.form["template"])

# FLAGGED: Jinja2 Template with f-string
from jinja2 import Template
def render_user_content(content):
    return Template(f"<div>{content}</div>").render()

# FLAGGED: string concatenation in render_template_string
@app.route("/hello")
def hello():
    return render_template_string("<p>Hello " + request.args.get("name") + "</p>")
```

## Remediation

1. **Use `render_template()` with a static template file.** This is the correct pattern. The user's data is passed as a variable to a pre-written template, not as the template itself. Template syntax in the variable value is not executed:

```python
from flask import render_template, request

@app.route("/greet")
def greet():
    name = request.args.get("name", "World")
    # SAFE: name is a variable passed to a static template
    return render_template("greet.html", name=name)
```

```html
{# templates/greet.html — Jinja2 escapes {{ name }} automatically (Flask default) #}
<h1>Hello {{ name }}!</h1>
```

2. **If you need to render user-provided template fragments, use a sandboxed environment.** Jinja2 provides a `SandboxedEnvironment` that restricts attribute access. It is not a complete security boundary but significantly raises the bar:

```python
from jinja2.sandbox import SandboxedEnvironment

sandbox_env = SandboxedEnvironment(autoescape=True)

def render_user_template(template_string: str, context: dict) -> str:
    try:
        tmpl = sandbox_env.from_string(template_string)
        return tmpl.render(**context)
    except Exception:
        return ""  # Do not leak error details to users
```

3. **For email templates, notification messages, or user-configurable content, use a restricted template language.** Libraries like `chevron` (Mustache) or `string.Template` provide variable substitution without template logic execution:

```python
import string

# SAFE: string.Template only substitutes $variables, does not execute code
template = string.Template("Hello $name, your order $order_id is ready.")
message = template.safe_substitute(name=user.name, order_id=order.id)
```

4. **Never expose `{{ config }}` or `{{ request }}` in templates.** Even in static template files, avoid rendering the Flask `config` or `request` objects directly — they contain sensitive data. Pass only the specific values a template needs.

## References

- [CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine](https://cwe.mitre.org/data/definitions/1336.html)
- [OWASP Server-Side Template Injection](https://owasp.org/www-community/attacks/Server_Side_Template_Injection)
- [OWASP ASVS V5 – Validation, Sanitization, and Encoding](https://owasp.org/www-project-application-security-verification-standard/)
- [PortSwigger – Server-side template injection](https://portswigger.net/web-security/server-side-template-injection)
- [Flask documentation – render_template](https://flask.palletsprojects.com/en/stable/api/#flask.render_template)
- [Jinja2 documentation – Sandbox](https://jinja.palletsprojects.com/en/stable/sandbox/)
- [Bandit B702 – Use of Jinja2 templates with autoescape=False](https://bandit.readthedocs.io/en/latest/plugins/b702_jinja2_autoescape_false.html)
- [CAPEC-242: Code Injection](https://capec.mitre.org/data/definitions/242.html)
- [MITRE ATT&CK T1190 – Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
