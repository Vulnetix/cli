---
title: "VNX-NODE-016 – ReDoS via User-Controlled Regular Expression"
description: "Detect Node.js code that passes user-controlled input to the RegExp constructor or string match/search methods, enabling Regular Expression Denial of Service (ReDoS) attacks."
---

## Overview

This rule detects cases where user-supplied HTTP request data (`req.query`, `req.body`, `req.params`) is passed directly to `new RegExp()`, `String.prototype.match()`, or `String.prototype.search()`. Because Node.js runs on a single-threaded event loop, a single malicious regex pattern with catastrophic backtracking can freeze the entire server for seconds to minutes, denying service to all other requests. This is CWE-1333 (Inefficient Regular Expression Complexity).

**Severity:** High | **CWE:** [CWE-1333 – Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html) | **CAPEC:** [CAPEC-197 – Exponential Data Expansion](https://capec.mitre.org/data/definitions/197.html)

## Why This Matters

ReDoS exploits the backtracking behaviour of most regex engines. Certain patterns — especially those with nested quantifiers like `(a+)+` or alternations sharing overlapping characters like `(a|aa)+` — cause the engine to explore an exponentially growing number of possible matches when the input does not match. JavaScript's V8 engine uses a backtracking NFA that is vulnerable to this class of attack.

Because Node.js uses a single-threaded event loop, a regex evaluation that takes 10 seconds blocks every other HTTP request queued behind it. An attacker needs only a single HTTP request with a crafted string to freeze the server, and the CPU cost is borne entirely by the server. Unlike most DoS attacks, this requires minimal network bandwidth and no botnet.

Real-world examples include vulnerabilities in `moment.js`, `minimatch`, `express-validator`, and many popular npm packages discovered through ReDoS audits. A pattern as simple as `^(\w+)+$` tested against `"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"` can take billions of steps.

**OWASP ASVS v4:** V12.5.2 — Verify that regular expressions from untrusted sources are rejected or executed in a sandboxed environment.

## What Gets Flagged

The rule matches lines where `new RegExp(` is combined with a `req.query`, `req.body`, or `req.params` reference, and lines where `.match()` or `.search()` is called with a request-derived argument.

```javascript
// FLAGGED: RegExp constructor with query parameter
app.get('/search', (req, res) => {
  const pattern = new RegExp(req.query.filter); // attacker controls the regex
  const results = data.filter(item => pattern.test(item.name));
  res.json(results);
});

// FLAGGED: String.match with user-supplied pattern
app.post('/validate', (req, res) => {
  const ok = inputString.match(req.body.pattern);
  res.json({ valid: !!ok });
});

// FLAGGED: String.search with request params
const idx = text.search(req.params.term);
```

Payload: `GET /search?filter=(a%2B)%2B$` with a string of 30 `a` characters followed by `b` causes the server event loop to stall.

## Remediation

1. **Never pass user input to `new RegExp()`.** Use a fixed, pre-compiled pattern instead:

   ```javascript
   // SAFE: fixed pattern, no user-controlled regex
   const SEARCH_PATTERN = /^[a-zA-Z0-9\s\-_]+$/;

   app.get('/search', (req, res) => {
     const term = req.query.term;
     if (typeof term !== 'string' || !SEARCH_PATTERN.test(term)) {
       return res.status(400).json({ error: 'Invalid search term' });
     }
     // Use the term as a plain substring match, not a regex
     const results = data.filter(item => item.name.includes(term));
     res.json(results);
   });
   ```

2. **If user-defined patterns are a product requirement**, validate and sanitise them with a safe regex library before execution. The `safe-regex` or `vuln-regex-detector` packages can detect catastrophically backtracking patterns at runtime:

   ```bash
   npm install safe-regex2
   ```

   ```javascript
   const safeRegex = require('safe-regex2');

   app.get('/search', (req, res) => {
     const userPattern = req.query.pattern;
     if (!safeRegex(userPattern)) {
       return res.status(400).json({ error: 'Unsafe regex pattern' });
     }
     const compiled = new RegExp(userPattern);
     const results = data.filter(item => compiled.test(item.name));
     res.json(results);
   });
   ```

3. **Use the `re2` library** (a binding to Google's RE2 engine) which provides linear-time regex matching by design and is immune to catastrophic backtracking. RE2 does not support backreferences or lookaheads:

   ```bash
   npm install re2
   ```

   ```javascript
   const RE2 = require('re2');

   app.get('/search', (req, res) => {
     try {
       // RE2 throws on patterns that would cause catastrophic backtracking
       const pattern = new RE2(req.query.filter, 'i');
       const results = data.filter(item => pattern.test(item.name));
       res.json(results);
     } catch (e) {
       res.status(400).json({ error: 'Invalid pattern' });
     }
   });
   ```

4. **Apply a timeout to regex evaluation** using a worker thread. The `node:worker_threads` module lets you run the regex in a separate thread and abort it after a deadline, preventing the event loop from being blocked:

   ```javascript
   // Offload potentially slow regex to a worker with a timeout
   const { Worker } = require('node:worker_threads');

   function regexWithTimeout(pattern, input, timeoutMs = 100) {
     return new Promise((resolve, reject) => {
       const worker = new Worker(`
         const { parentPort, workerData } = require('worker_threads');
         const re = new RegExp(workerData.pattern);
         parentPort.postMessage(re.test(workerData.input));
       `, { eval: true, workerData: { pattern, input } });

       const timer = setTimeout(() => {
         worker.terminate();
         reject(new Error('Regex timeout'));
       }, timeoutMs);

       worker.on('message', result => { clearTimeout(timer); resolve(result); });
       worker.on('error', err => { clearTimeout(timer); reject(err); });
     });
   }
   ```

5. **Validate input against a strict allowlist** before using it in any pattern-matching context. A simple length limit and character allowlist reduces the backtracking search space dramatically.

## References

- [CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html)
- [CAPEC-197: Exponential Data Expansion](https://capec.mitre.org/data/definitions/197.html)
- [OWASP Regular Expression Denial of Service (ReDoS)](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
- [OWASP ASVS v4 – V12.5 Deserialization and ReDoS](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [safe-regex2 – npm package for safe regex detection](https://www.npmjs.com/package/safe-regex2)
- [re2 – Node.js bindings to Google RE2 (linear-time regex)](https://www.npmjs.com/package/re2)
- [vuln-regex-detector – npm package](https://www.npmjs.com/package/vuln-regex-detector)
- [MITRE ATT&CK T1499.004 – Application or System Exploitation](https://attack.mitre.org/techniques/T1499/004/)
