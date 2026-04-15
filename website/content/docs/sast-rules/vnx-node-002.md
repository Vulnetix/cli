---
title: "VNX-NODE-002 – eval() or new Function() in JavaScript"
description: "Detects use of eval() and new Function() which execute arbitrary JavaScript and enable remote code execution when called with user-controlled input."
---

## Overview

This rule detects calls to `eval()` and `new Function()` in JavaScript and TypeScript source files. Both constructs compile and execute a string as JavaScript at runtime. When any part of that string is derived from user input — a query parameter, request body, WebSocket message, or any other external source — an attacker can run arbitrary code with the full privileges of the Node.js process. This maps to CWE-94 (Improper Control of Generation of Code).

**Severity:** High | **CWE:** [CWE-94 – Improper Control of Generation of Code](https://cwe.mitre.org/data/definitions/94.html)

## Why This Matters

Code injection via `eval()` is one of the most direct paths to full server compromise. An attacker who can control the argument to `eval()` can read environment variables (stealing secrets and API keys), spawn child processes to execute OS commands, open reverse shells, exfiltrate files, or pivot to internal services. Unlike SQL injection, which is constrained to database operations, JavaScript code injection has unrestricted access to the Node.js runtime and everything it can reach.

The `new Function()` constructor is equally dangerous and is frequently used as an obfuscated substitute for `eval()`. Code like `new Function('return ' + userInput)()` is functionally identical to `eval(userInput)`. Sandboxing libraries such as `vm2` were once considered mitigations, but every version has been bypassed via prototype chain manipulation or native module escapes — the vm2 project was officially abandoned in 2023 following critical sandbox-escape CVEs. There is no reliable sandbox for untrusted JavaScript within Node.js.

## What Gets Flagged

The rule scans all `.js`, `.ts`, `.jsx`, `.tsx`, `.mjs`, and `.cjs` files for the patterns `eval(` and `new Function(`.

```javascript
// FLAGGED: eval with user input
app.post('/calculate', (req, res) => {
  const result = eval(req.body.expression);
  res.json({ result });
});

// FLAGGED: new Function used to build dynamic logic
const fn = new Function('x', req.query.body);
fn(42);
```

## Remediation

1. **Remove `eval()` and `new Function()` entirely.** In virtually every legitimate use case there is a safer alternative that does not require runtime code compilation.

2. **For mathematical expressions**, use a dedicated, safe evaluator library that parses an AST without executing code:

   ```javascript
   // SAFE: use mathjs or expr-eval for expression evaluation
   import { evaluate } from 'mathjs';

   app.post('/calculate', (req, res) => {
     try {
       const result = evaluate(req.body.expression); // parses, does not eval
       res.json({ result });
     } catch (err) {
       res.status(400).json({ error: 'Invalid expression' });
     }
   });
   ```

3. **For dynamic configuration or plugins**, use JSON for data and require plugins from a fixed local path, never from user-supplied strings:

   ```javascript
   // SAFE: load plugins from a controlled directory, never from user input
   const PLUGIN_DIR = path.resolve(__dirname, 'plugins');
   const pluginName = req.query.plugin.replace(/[^a-z0-9-]/gi, '');
   const pluginPath = path.join(PLUGIN_DIR, pluginName);
   if (!pluginPath.startsWith(PLUGIN_DIR)) throw new Error('Invalid plugin');
   const plugin = require(pluginPath);
   ```

4. **For template rendering**, pass user data as context variables — never as the template string itself (see also VNX-NODE-011):

   ```javascript
   // SAFE: template is a static string; user data is only context
   const template = fs.readFileSync('./templates/email.html', 'utf8');
   const rendered = ejs.render(template, { name: req.body.name });
   ```

5. **Apply a Content Security Policy** header that includes `script-src` without `'unsafe-eval'` to prevent client-side `eval()` as a defence-in-depth measure.

## References

- [CWE-94: Improper Control of Generation of Code](https://cwe.mitre.org/data/definitions/94.html)
- [CAPEC-35: Leverage Executable Code in Non-Executable Files](https://capec.mitre.org/data/definitions/35.html)
- [vm2 project abandoned – critical sandbox escape](https://github.com/patriksimek/vm2/issues/533)
- [mathjs safe expression evaluation](https://mathjs.org/docs/expressions/security.html)
- [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [MDN – eval() security concerns](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!)
- [MITRE ATT&CK T1059.007 – JavaScript](https://attack.mitre.org/techniques/T1059/007/)
