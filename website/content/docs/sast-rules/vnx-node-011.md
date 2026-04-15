---
title: "VNX-NODE-011 – Node.js Server-Side Template Injection"
description: "Detects user input passed as the template string to render/compile functions in ejs, pug, Handlebars, or nunjucks, enabling server-side template injection and remote code execution."
---

## Overview

This rule detects cases where user-controlled request data (`req.*` or `request.*`) is passed as the first argument to template engine `render` or `compile` functions — `ejs.render()`, `pug.render()`, `Handlebars.compile()`, `nunjucks.renderString()`, `new Function()`, or `eval()`. When a user can control the template string itself (rather than just the data bound into the template), they can embed template directives that execute arbitrary server-side code. This is CWE-1336 (Improper Neutralization of Special Elements Used in a Template Engine).

**Severity:** Critical | **CWE:** [CWE-1336 – Improper Neutralization of Special Elements Used in a Template Engine](https://cwe.mitre.org/data/definitions/1336.html)

## Why This Matters

Server-side template injection (SSTI) is a critical remote code execution vulnerability. Template engines are designed to execute code within their template syntax — that is their purpose. When user input becomes the template, the user gains the ability to call any function available in the template engine's context. In EJS, a payload like `<%= process.env.DATABASE_PASSWORD %>` leaks secrets. A payload like `<%= require('child_process').execSync('id').toString() %>` executes OS commands. The same applies to Pug (`#{root.process.mainModule.require('child_process').execSync('id')}`), Handlebars, and Nunjucks.

This is a common mistake in applications that offer users a "custom email template", "report template", or "message format" feature. Developers think they are providing a restricted formatting language but are actually handing users a full code execution primitive.

## What Gets Flagged

The rule matches lines where `ejs.render(req.`, `pug.render(req.`, `Handlebars.compile(req.`, `nunjucks.renderString(req.`, `new Function(req.`, or `eval(req.` appear (also `request.` variants).

```javascript
// FLAGGED: user input as EJS template string
app.post('/preview', (req, res) => {
  const rendered = ejs.render(req.body.template, { user: currentUser });
  res.send(rendered);
});

// FLAGGED: user input compiled by Handlebars
app.post('/email-preview', (req, res) => {
  const template = Handlebars.compile(req.body.template);
  res.send(template({ name: 'Test' }));
});
```

Payload: `<%= require('child_process').execSync('cat /etc/passwd').toString() %>` — the server returns the contents of `/etc/passwd`.

## Remediation

1. **Never use user input as the template string.** Templates must be static files stored on the server, loaded from disk or a controlled database column that only administrators can modify.

   ```javascript
   // SAFE: template is a static file; user data is only context variables
   const path = require('path');
   const ejs = require('ejs');

   app.post('/preview', async (req, res) => {
     // Load the template from a fixed, trusted path
     const templatePath = path.resolve(__dirname, 'templates', 'email.ejs');
     const rendered = await ejs.renderFile(templatePath, {
       name: req.body.name,
       message: req.body.message,
     });
     res.send(rendered);
   });
   ```

2. **Use `ejs.renderFile()` instead of `ejs.render()` wherever possible** — it takes a file path, making it structurally impossible to accidentally pass a user string as the template:

   ```javascript
   // SAFE: renderFile only accepts paths, not template strings
   const html = await ejs.renderFile('./views/report.ejs', {
     data: safeData,
   });
   ```

3. **For user-defined template content, use a sandboxed, logic-less template engine** such as Mustache, which has no code execution primitives — only variable substitution and conditionals:

   ```javascript
   // SAFE: Mustache is logic-less — no code execution possible
   const Mustache = require('mustache');
   const rendered = Mustache.render(req.body.template, {
     name: req.body.name,  // only safe variable substitution
   });
   ```

4. **Validate and restrict template variable names.** If you must allow user-defined templates with variable binding, build a parser that only allows your own `{{variable}}` syntax and rejects anything else — never pass the string to a template engine.

5. **Apply Content Security Policy and output encoding** as defence-in-depth to limit the impact of any XSS in template output, even if SSTI is prevented.

## References

- [CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine](https://cwe.mitre.org/data/definitions/1336.html)
- [CAPEC-242: Code Injection](https://capec.mitre.org/data/definitions/242.html)
- [PortSwigger – Server-side template injection](https://portswigger.net/web-security/server-side-template-injection)
- [EJS renderFile documentation](https://ejs.co/#api)
- [Mustache.js – logic-less templates](https://github.com/janl/mustache.js)
- [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [MITRE ATT&CK T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
