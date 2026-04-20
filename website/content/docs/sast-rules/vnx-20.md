---
title: "VNX-20 – Improper Input Validation"
description: "Detect user-controlled data flowing into sensitive application sinks without any validation or sanitisation step across multiple languages and frameworks."
---

## Overview

This rule flags locations where user-supplied data — from HTTP requests, form fields, query parameters, cookies, or URL segments — is read and used directly without any visible validation or sanitisation. Failing to validate input is the root cause of the majority of injection vulnerabilities: SQL injection, command injection, path traversal, XSS, and more all begin with untrusted data being treated as trustworthy. This maps to [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html).

**Severity:** High | **CWE:** [CWE-20 – Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

## Why This Matters

Every piece of data that originates outside your application boundary is potentially hostile. A developer who trusts that `req.body.username` contains only a valid username, or that `$_GET['id']` contains only an integer, is making an assumption that an attacker will deliberately violate. Input validation is not about preventing one class of attack — it is the primary defence against an enormous range of exploits. MITRE ATT&CK T1190 (Exploit Public-Facing Application) covers the majority of web-application attacks, virtually all of which begin with invalid or malicious input reaching a sensitive operation.

The rule deliberately casts a wide net: it flags `req.body.`, `request.GET[`, `$_POST[`, `getParameter(`, and equivalents in Go, Java, Ruby, and C#. Any line where user input is accessed without an obvious validation or escape call alongside it is reported for human review.

## What Gets Flagged

```javascript
// FLAGGED: Express — raw query parameter used in a database query
app.get('/search', (req, res) => {
    const term = req.query.term;        // no validation
    db.query('SELECT * FROM items WHERE name = ' + term, (err, rows) => {
        res.json(rows);
    });
});
```

```python
# FLAGGED: Flask — form field passed directly to a shell command
from flask import request
import subprocess

@app.route('/ping', methods=['POST'])
def ping():
    host = request.form['host']         # no validation
    result = subprocess.run(['ping', host], capture_output=True)
    return result.stdout
```

```php
<?php
// FLAGGED: PHP — superglobal used directly in a file include
$page = $_GET['page'];                  // no validation
include($page . '.php');
```

```java
// FLAGGED: Java Servlet — request parameter printed without escaping
String name = request.getParameter("name");  // no validation
out.println("<h1>Hello, " + name + "</h1>");
```

## Remediation

1. **Validate type, length, format, and range.** For every input, define what "valid" means before processing it.

```javascript
// SAFE: Express — validate before use
const { body, validationResult } = require('express-validator');

app.post('/search', [
    body('term').isAlphanumeric().isLength({ max: 100 }),
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const term = req.body.term;  // validated
    // ...
});
```

```python
# SAFE: Flask — validate with WTForms or manual check
from flask import request, abort
import re

@app.route('/ping', methods=['POST'])
def ping():
    host = request.form.get('host', '')
    if not re.match(r'^[a-zA-Z0-9.\-]{1,253}$', host):
        abort(400, 'Invalid hostname')
    result = subprocess.run(['ping', '-c', '1', host], capture_output=True)
    return result.stdout
```

```php
<?php
// SAFE: PHP — allowlist of permitted page names
$allowed = ['home', 'about', 'contact'];
$page = $_GET['page'] ?? '';
if (!in_array($page, $allowed, true)) {
    http_response_code(400);
    exit('Invalid page');
}
include(__DIR__ . '/pages/' . $page . '.php');
```

2. **Use framework validation helpers.** Laravel Validator, Django Forms, Spring Validator, and similar provide declarative validation with detailed error messages and reduce hand-rolled bugs.

3. **Adopt a defence-in-depth approach.** Validate at the boundary, encode at the output, and use parameterised APIs (prepared statements, shell argument arrays) for sensitive sinks. No single layer is sufficient on its own.

4. **Reject rather than sanitise where possible.** Allowlist-based validation (only accept characters in a defined set) is more robust than blocklist sanitisation (strip known bad characters).

## References

- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [OWASP ASVS V5 – Validation, Sanitization and Encoding](https://owasp.org/www-project-application-security-verification-standard/)
- [CAPEC-88: OS Command Injection](https://capec.mitre.org/data/definitions/88.html)
- [MITRE ATT&CK T1190 – Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
