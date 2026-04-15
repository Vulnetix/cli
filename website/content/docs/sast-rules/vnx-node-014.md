---
title: "VNX-NODE-014 – NoSQL Injection in MongoDB"
description: "Detects unsanitized user input (req.body, req.query) passed directly to MongoDB query methods, enabling NoSQL injection attacks that bypass authentication or extract arbitrary data."
---

## Overview

This rule detects MongoDB query method calls — `find()`, `findOne()`, `findOneAndUpdate()`, `updateOne()`, `deleteOne()`, `deleteMany()` — where the filter argument is supplied directly from `req.body` or `req.query`. Unlike SQL injection, which manipulates a query string, NoSQL injection exploits the fact that MongoDB query filters are JavaScript objects: an attacker who can control the filter object can inject MongoDB query operators (`$where`, `$gt`, `$ne`, `$regex`) to bypass authentication, extract data conditionally, or match unintended documents. This is CWE-943 (Improper Neutralization of Special Elements in Data Query Logic).

**Severity:** High | **CWE:** [CWE-943 – Improper Neutralization of Special Elements in Data Query Logic](https://cwe.mitre.org/data/definitions/943.html) | **CAPEC:** [CAPEC-676 – NoSQL Injection](https://capec.mitre.org/data/definitions/676.html)

## Why This Matters

NoSQL injection via MongoDB operators is a well-documented and frequently exploited attack. The classic authentication bypass works because a developer writes `User.findOne(req.body)` expecting `{ username: "alice", password: "secret" }`, but an attacker sends `{ "username": "admin", "password": { "$ne": "" } }`. The `$ne` (not-equal) operator matches any user whose password is not an empty string — which is all of them — so the query returns the first admin user without knowing the password.

The `$where` operator is even more dangerous: it accepts a JavaScript expression that is evaluated server-side by the MongoDB JavaScript engine. An attacker who can inject a `$where` clause can execute arbitrary JavaScript within the database process context, potentially causing denial of service through infinite loops or leaking data through timing side channels.

Real-world consequences include complete authentication bypass, unauthorised data exfiltration, and cascading data destruction via operator-injected `deleteMany` filters. Because MongoDB drivers accept any JavaScript object as a query filter, there is no layer between user input and query execution when request bodies are passed directly.

**OWASP ASVS v4:** V5.3.4 — Verify that the application protects against NoSQL injection attacks.

## What Gets Flagged

The rule matches lines where MongoDB query methods receive `req.body` or `req.query` as a direct argument.

```javascript
// FLAGGED: findOne with req.body directly as filter
app.post('/login', async (req, res) => {
  const user = await User.findOne(req.body);
  if (user) res.json({ token: generateToken(user) });
  else res.status(401).json({ error: 'Invalid credentials' });
});

// FLAGGED: find with req.query as filter
app.get('/users', async (req, res) => {
  const users = await User.find(req.query);
  res.json(users);
});

// FLAGGED: deleteMany with body spread
await Collection.deleteMany(req.body);

// FLAGGED: updateOne with query object from request
await Item.updateOne(req.query, { $set: { active: false } });
```

Payload for login bypass: `POST /login` with body `{ "username": "admin", "password": { "$ne": null } }` — logs in as admin without the password.

## Remediation

1. **Extract only the specific fields your query needs** from the request object. Never spread or pass the entire `req.body` or `req.query` to a query method:

   ```javascript
   // SAFE: extract and validate specific fields
   app.post('/login', async (req, res) => {
     const { username, password } = req.body;

     // Type-check: both must be strings
     if (typeof username !== 'string' || typeof password !== 'string') {
       return res.status(400).json({ error: 'Invalid input' });
     }

     const user = await User.findOne({ username });
     if (!user || !await bcrypt.compare(password, user.passwordHash)) {
       return res.status(401).json({ error: 'Invalid credentials' });
     }
     res.json({ token: generateToken(user) });
   });
   ```

2. **Enforce string types for all user-supplied filter fields.** MongoDB operators are objects, not strings, so a simple `typeof` check blocks operator injection entirely:

   ```javascript
   // SAFE: type guard blocks operator objects such as { $ne: null }
   function assertString(value, fieldName) {
     if (typeof value !== 'string') {
       throw new Error(`${fieldName} must be a string`);
     }
     return value;
   }

   app.get('/users', async (req, res) => {
     const email = assertString(req.query.email, 'email');
     const users = await User.find({ email });
     res.json(users);
   });
   ```

3. **Disable the MongoDB JavaScript engine at the server level.** In `mongod.conf`, set `security.javascriptEnabled: false`. This removes the `$where` attack surface entirely and has no impact if you are not using server-side JavaScript:

   ```yaml
   # mongod.conf
   security:
     javascriptEnabled: false
   ```

4. **Use a validation library to enforce schema shape before the query.** Libraries like `joi`, `zod`, or `express-validator` can reject input objects containing unexpected keys or non-string values:

   ```javascript
   // SAFE: zod schema rejects operator objects automatically
   import { z } from 'zod';

   const LoginSchema = z.object({
     username: z.string().min(1).max(64),
     password: z.string().min(1).max(128),
   });

   app.post('/login', async (req, res) => {
     const result = LoginSchema.safeParse(req.body);
     if (!result.success) return res.status(400).json({ error: 'Invalid input' });
     const { username, password } = result.data;
     // safe to query — only string values reach the DB layer
   });
   ```

5. **Sanitize MongoDB queries with `mongo-sanitize`** as an additional defence-in-depth middleware layer that strips any key beginning with `$`:

   ```bash
   npm install mongo-sanitize
   ```

   ```javascript
   const sanitize = require('mongo-sanitize');

   app.use((req, res, next) => {
     req.body = sanitize(req.body);
     req.query = sanitize(req.query);
     next();
   });
   ```

   Note: `mongo-sanitize` is a safety net, not a primary defence. Always validate and extract specific fields first.

## References

- [CWE-943: Improper Neutralization of Special Elements in Data Query Logic](https://cwe.mitre.org/data/definitions/943.html)
- [CAPEC-676: NoSQL Injection](https://capec.mitre.org/data/definitions/676.html)
- [OWASP Testing for NoSQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection)
- [OWASP ASVS v4 – V5.3.4 NoSQL Injection](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [mongo-sanitize – strip MongoDB operator keys from user input](https://www.npmjs.com/package/mongo-sanitize)
- [MongoDB security – disable server-side JavaScript](https://www.mongodb.com/docs/manual/core/server-side-javascript/)
- [zod – TypeScript-first schema validation](https://zod.dev/)
- [MITRE ATT&CK T1190 – Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
