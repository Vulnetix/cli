---
title: "VNX-NODE-011 – Node.js Server-Side Template Injection"
description: "Reports a template engine (ejs, pug/jade, Handlebars, nunjucks, lodash _.template, doT, Mustache, Eta, Squirrelly, swig) compiling or rendering a template source taken from req.query/body/params or Koa ctx, directly or through a variable or a concatenation built from one. User data passed as the render context is not reported."
---

## Overview

This rule detects cases where user-controlled request data (`req.*` or `request.*`) is passed as the first argument to template engine `render` or `compile` functions — `ejs.render()`, `pug.render()`, `Handlebars.compile()`, `nunjucks.renderString()`, lodash `_.template()`, doT, Mustache, Eta and swig, either directly or through a variable or concatenation built from the request a few lines above. When a user can control the template string itself (rather than just the data bound into the template), they can embed template directives that execute arbitrary server-side code. This is CWE-1336 (Improper Neutralization of Special Elements Used in a Template Engine).

**Severity:** Critical | **CWE:** [CWE-1336 – Improper Neutralization of Special Elements Used in a Template Engine](https://cwe.mitre.org/data/definitions/1336.html)

## Why This Matters

Server-side template injection (SSTI) is a critical remote code execution vulnerability. Template engines are designed to execute code within their template syntax — that is their purpose. When user input becomes the template, the user gains the ability to call any function available in the template engine's context. In EJS, a payload like `<%= process.env.DATABASE_PASSWORD %>` leaks secrets. A payload like `<%= require('child_process').execSync('id').toString() %>` executes OS commands. The same applies to Pug (`#{root.process.mainModule.require('child_process').execSync('id')}`), Handlebars, and Nunjucks.

This is a common mistake in applications that offer users a "custom email template", "report template", or "message format" feature. Developers think they are providing a restricted formatting language but are actually handing users a full code execution primitive.

## What Gets Flagged

The template source (the first argument of `render`, `compile` or `renderString`) must come from the request. Data passed as the second, context argument is the safe use and is not reported.

```javascript
// FLAGGED: the client supplies the template
res.send(ejs.render(req.body.template, { user: req.user }));
res.send(pug.render(req.query.tpl));
const fn = Handlebars.compile(req.body.layout);

// FLAGGED: template built from request input
const name = req.query.name;
const tpl = 'Hello ' + name + '!';
res.send(nunjucks.renderString(tpl, {}));
```

Not flagged: `res.render('profile', { name: req.query.name })`, `ejs.render(fileTemplate, { user: req.body })`, `pug.renderFile(...)`, and constant templates such as `nunjucks.renderString('Hello {{ name }}', { name: req.query.name })`. `eval()` and `new Function()` are VNX-NODE-002.

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
