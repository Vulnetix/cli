---
title: "VNX-95 – Template Injection (Eval Injection)"
description: "HTTP request data becomes the source of a Jinja2, Mako, Django, EJS, Pug, Handlebars, Nunjucks, lodash, ERB, Erubi, Haml, Slim or Rails render inline: template, directly or through a variable."
---

## Overview

This rule flags server-side template engine calls — Jinja2's `render_template_string()`, Mako's `Template()`, Node.js Pug/EJS/Handlebars compile/render functions, and Ruby's `ERB.new()`, Erubi, Haml, Slim and Rails `render inline:` — whose template source (first argument) is HTTP request data, used directly or through a variable assigned from it in the 25 lines above. Request data passed as template context is not reported. Server-Side Template Injection (SSTI) allows an attacker to inject template directives that are evaluated by the template engine with full application privileges, often leading to arbitrary code execution. This maps to [CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')](https://cwe.mitre.org/data/definitions/95.html).

**Severity:** Critical | **CWE:** [CWE-95 – Eval Injection / Template Injection](https://cwe.mitre.org/data/definitions/95.html)

## Why This Matters

SSTI is frequently confused with XSS, but the consequences are far worse: instead of JavaScript executing in a visitor's browser, arbitrary code executes on the server. In Jinja2, the payload `{{''.__class__.__mro__[1].__subclasses__()}}` enumerates all Python classes; from there an attacker can reach `subprocess` and execute OS commands. In Pug (formerly Jade), `-` prefix lines execute arbitrary JavaScript. The vulnerability is subtle because the same template engine that is safe when rendering `render_template('page.html', name=name)` becomes catastrophically dangerous when the template source itself comes from user input via `render_template_string(name)`.

## What Gets Flagged

The template SOURCE (first argument) carries request data, directly or through a variable assigned from it:

```python
# FLAGGED
name = request.args.get("name", "guest")
page = "<h1>Hello " + name + "</h1>"
return render_template_string(page)
tpl = env.from_string(request.form["body"])
```

```javascript
// FLAGGED
res.send(ejs.render(req.query.tpl, {}));
const t = Handlebars.compile(`<div>${req.body.msg}</div>`);
```

```ruby
# FLAGGED
html = ERB.new(params[:template]).result(binding)
render inline: "<p>#{params[:message]}</p>"
```

Not flagged: request data passed as context (`render_template_string("<h1>{{ name }}</h1>", name=name)`, `ejs.render(layout, { name: req.query.name })`), templates read from files, and Python `string.Template`.

## Remediation

1. **Never use `render_template_string()` or equivalent with user input.** Pass user data as context variables to a static template file.

```python
# SAFE: Flask/Jinja2 — static template file, user data as context
from flask import render_template

@app.route('/greet')
def greet():
    name = request.args.get('name', '')
    # name is passed as a variable, not as part of the template syntax
    return render_template('greet.html', name=name)
    # greet.html: <h1>Hello {{ name }}</h1>  — Jinja2 auto-escapes this
```

```python
# SAFE: Jinja2 sandbox for when dynamic templates are genuinely required
from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment()
# SandboxedEnvironment restricts access to Python internals,
# but still do not pass user data as the template source if avoidable.
template = env.from_string(developer_controlled_template)
output = template.render(user_data=safe_context_dict)
```

2. **For Node.js template engines, precompile from static files.**

```javascript
// SAFE: Pug — compile from a static file
const pug = require('pug');
const compiledFn = pug.compileFile('views/greet.pug');

app.get('/greet', (req, res) => {
    res.send(compiledFn({ name: req.query.name }));  // name is a variable, not template
});
```

```javascript
// SAFE: EJS — render from a file
app.get('/preview', (req, res) => {
    res.render('preview', { user: req.user, data: sanitizedData });
    // views/preview.ejs accesses <%= user.name %> — EJS escapes by default
});
```

3. **For Ruby ERB, load templates from disk.**

```ruby
# SAFE: Load template from a controlled file path
template = ERB.new(File.read(Rails.root.join('app/views/mail/template.html.erb')))
output = template.result_with_hash(name: safe_name)
```

4. **Apply a Content Security Policy (CSP).** Even if SSTI results in reflected XSS rather than RCE, a strict CSP limits the damage.

## References

- [CWE-95: Eval Injection](https://cwe.mitre.org/data/definitions/95.html)
- [OWASP Server-Side Template Injection](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection)
- [PortSwigger: Server-Side Template Injection](https://portswigger.net/web-security/server-side-template-injection)
- [Jinja2 Sandbox documentation](https://jinja.palletsprojects.com/en/3.1.x/sandbox/)
- [CAPEC-242: Code Injection](https://capec.mitre.org/data/definitions/242.html)
- [MITRE ATT&CK T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
