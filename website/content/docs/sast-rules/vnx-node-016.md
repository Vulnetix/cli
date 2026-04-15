---
title: "VNX-NODE-016 – ReDoS via User-Controlled Regular Expression"
description: "Detect Node.js code that passes user-controlled input to the RegExp constructor or string match/search methods, enabling Regular Expression Denial of Service (ReDoS) attacks."
---

## Overview

This rule flags JavaScript/TypeScript code where `new RegExp()` receives user input from `req.query`, `req.body`, or `req.params`, and where `string.match()` or `string.search()` is called with user-controlled patterns. An attacker can supply a regex with catastrophic backtracking that freezes the Node.js event loop for seconds or minutes, denying service to all concurrent users. This maps to [CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html).

**Severity:** High | **CWE:** [CWE-1333 – Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html)

## Why This Matters

Node.js runs JavaScript on a single event loop. If a regex operation takes 10 seconds due to catastrophic backtracking, the entire server is unresponsive for those 10 seconds. Patterns like `(a+)+$` matched against `"aaaaaaaaaaaaaaaaaaaaa!"` cause exponential backtracking. When the attacker controls the regex pattern itself, they can trivially construct a pattern that will hang indefinitely.

## What Gets Flagged

```javascript
// FLAGGED: user input as regex pattern
const pattern = new RegExp(req.query.search);
const results = data.filter(item => pattern.test(item.name));

// FLAGGED: user input in string.match
const match = text.match(req.body.pattern);
```

## Remediation

1. **Never use user input as a regex pattern.** Use string operations like `includes()`, `startsWith()`, or `indexOf()` for user-driven search:

```javascript
// SAFE: string methods instead of regex
const results = data.filter(item =>
  item.name.toLowerCase().includes(req.query.search.toLowerCase())
);
```

2. **If regex is necessary, use a safe regex library** like `re2` (Google RE2 bindings for Node.js) which guarantees linear-time matching:

```javascript
const RE2 = require('re2');
const pattern = new RE2(req.query.search); // linear-time, no backtracking
```

3. **Escape user input before embedding in a regex:**

```javascript
function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
const pattern = new RegExp(escapeRegex(req.query.search));
```

## References

- [CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html)
- [OWASP Regular Expression Denial of Service](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
- [Node.js RE2 bindings](https://github.com/uhop/node-re2)
- [CAPEC-197: Exponential Data Expansion](https://capec.mitre.org/data/definitions/197.html)
- [MITRE ATT&CK T1499.004 – Application or System Exploitation](https://attack.mitre.org/techniques/T1499/004/)
