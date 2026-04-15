---
title: "VNX-NODE-006 – Prototype Pollution via Merge"
description: "Detects deep-merge operations (lodash _.merge, _.defaultsDeep, Object.assign) applied to user-controlled input, which can inject properties into Object.prototype and cause denial of service or remote code execution."
---

## Overview

This rule detects deep-merge and deep-assign operations — `_.merge()`, `_.defaultsDeep()`, `_.set()`, `lodash.merge()`, and `Object.assign({}, req.body/req.query)` — applied to user-controlled input such as `req.body` or `req.query`. If the user input contains a key like `__proto__` or `constructor`, the merge operation walks the prototype chain and injects properties into `Object.prototype` itself, polluting every object in the process. This is CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes).

**Severity:** High | **CWE:** [CWE-915 – Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)

## Why This Matters

Prototype pollution is deceptively powerful. When `Object.prototype` is modified, every plain object (`{}`) in the runtime inherits the injected property. A payload like `{ "__proto__": { "isAdmin": true } }` can elevate privileges silently across the entire application — any subsequent `if (user.isAdmin)` check becomes true for all users, not just administrators.

In more severe cases, polluting properties used by template engines, module loaders, or serialization libraries can escalate to remote code execution. Multiple CVEs have been disclosed against lodash (CVE-2019-10744, CVE-2020-8203), jQuery (CVE-2019-11358), and other widely used libraries due to prototype pollution in their merge implementations. Lodash versions below 4.17.21 are known to be exploitable. Simply upgrading may not be sufficient if your own code performs the merge.

## What Gets Flagged

The rule matches lines containing any of: `_.merge(`, `_.defaultsDeep(`, `_.set(`, `lodash.merge(`, `merge(target, req.body`, `merge(target, req.query`, or `Object.assign({}, req.body`.

```javascript
// FLAGGED: lodash merge with user-controlled body
const _ = require('lodash');
app.post('/settings', (req, res) => {
  _.merge(defaultConfig, req.body);
  res.json(defaultConfig);
});

// FLAGGED: Object.assign spreading request body
const merged = Object.assign({}, req.body, internalDefaults);
```

An attacker sends: `{ "__proto__": { "admin": true } }` and every object in the application now has `.admin === true`.

## Remediation

1. **Validate and strip prototype-polluting keys before merging.** Reject any input that contains `__proto__`, `constructor`, or `prototype` as a key at any nesting level:

   ```javascript
   // SAFE: strip dangerous keys before merging
   function sanitizeInput(obj) {
     const dangerous = new Set(['__proto__', 'constructor', 'prototype']);
     if (typeof obj !== 'object' || obj === null) return obj;
     return Object.fromEntries(
       Object.entries(obj)
         .filter(([k]) => !dangerous.has(k))
         .map(([k, v]) => [k, sanitizeInput(v)])
     );
   }

   app.post('/settings', (req, res) => {
     const safe = sanitizeInput(req.body);
     _.merge(defaultConfig, safe);
     res.json(defaultConfig);
   });
   ```

2. **Use `Object.create(null)` for dictionary objects** that will receive arbitrary keys. Objects created with `null` prototype have no `__proto__` property, so they cannot be used as a pollution vector:

   ```javascript
   // SAFE: null-prototype object cannot pollute Object.prototype
   const userSettings = Object.create(null);
   Object.assign(userSettings, req.body);
   ```

3. **Guard lookups with `Object.prototype.hasOwnProperty.call()`** rather than `obj.hasOwnProperty()`, since a polluted object may shadow that method:

   ```javascript
   // SAFE: explicit hasOwnProperty check
   if (Object.prototype.hasOwnProperty.call(obj, key)) {
     // process key
   }
   ```

4. **Upgrade lodash to 4.17.21 or higher** and use its `_.mergeWith` with a customiser that skips dangerous keys:

   ```javascript
   // SAFE: mergeWith customiser blocks prototype keys
   _.mergeWith(target, source, (objValue, srcValue, key) => {
     if (['__proto__', 'constructor', 'prototype'].includes(key)) {
       return objValue; // keep existing, ignore source
     }
   });
   ```

5. **Use a JSON Schema validator** (e.g., `ajv`) to enforce the exact shape of request bodies before any merge operation, rejecting inputs with unexpected keys entirely:

   ```bash
   npm install ajv
   ```

## References

- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
- [CVE-2019-10744 – lodash prototype pollution](https://nvd.nist.gov/vuln/detail/CVE-2019-10744)
- [CVE-2020-8203 – lodash prototype pollution](https://nvd.nist.gov/vuln/detail/CVE-2020-8203)
- [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [HackerOne – Prototype Pollution report writeup](https://hackerone.com/reports/380185)
- [lodash documentation – merge](https://lodash.com/docs/4.17.15#merge)
- [MITRE ATT&CK T1190 – Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
