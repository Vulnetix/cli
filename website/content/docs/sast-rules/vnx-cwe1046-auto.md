---
title: "VNX-1046 – Open Redirect to Untrusted Site"
description: "Detects HTTP redirect functions across Go, Java, Node.js, PHP, and Python that may forward users to attacker-controlled URLs when redirect targets are derived from unvalidated input."
---

## Overview

VNX-1046 is an auto-generated broad-pattern rule that searches for HTTP redirect operations across Go, Java, Node.js, PHP, and Python source files. The rule targets `http.Redirect` in Go, `sendRedirect` in Java, `res.redirect` in Node.js, `header` (with `Location:`) in PHP, and `redirect` in Python (Flask/Django). These are associated with [CWE-1046](https://cwe.mitre.org/data/definitions/1046.html) in the rule metadata.

Note: CWE-1046 in MITRE's catalog covers "Creation of Immutable Text Using String Concatenation." The security concern this rule actually detects — open redirects — maps to [CWE-601: URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html). The CWE mapping is a known limitation of this auto-generated rule.

All flagged patterns are normal redirect APIs; findings must be reviewed to determine whether the redirect target is validated against an allowlist before use.

**Severity:** Medium | **CWE:** [CWE-1046](https://cwe.mitre.org/data/definitions/1046.html) | **OWASP:** [A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

## Why This Matters

Open redirects are exploited as a link-laundering primitive in phishing campaigns. An attacker constructs a URL to a trusted domain (e.g., `https://yourapp.com/login?next=https://evil.com`) that redirects the victim to a malicious site. Because the initial URL belongs to a legitimate domain, security tools, email filters, and users are less likely to flag it as suspicious.

Open redirects also assist OAuth phishing attacks where the redirect URL parameter is manipulated to intercept authorisation codes or access tokens.

## What Gets Flagged

The rule scans Go, Java, Node.js, PHP, and Python source files for redirect patterns:

```python
# FLAGGED: Flask redirect with user-supplied URL
from flask import redirect, request
return redirect(request.args.get('next'))
```

```javascript
// FLAGGED: Express redirect with query param
app.get('/login', (req, res) => {
    res.redirect(req.query.returnUrl);
});
```

```php
// FLAGGED: PHP Location header from input
header('Location: ' . $_GET['redirect']);
exit;
```

## Remediation

1. Never redirect to a URL taken directly from user-supplied input (query parameters, form fields, headers).
2. Implement an allowlist of permitted redirect destinations and validate the target against it before redirecting.
3. If relative redirects are sufficient (e.g., post-login navigation within the same application), strip any scheme or authority from the target and treat it as a path only.
4. Use indirect redirect maps: store valid destinations server-side keyed by an opaque token, and accept only the token from user input.
5. For OAuth flows, register exact redirect URIs and reject any redirect that is not an exact match.

## References

- [CWE-601: URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html)
- [OWASP Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [OWASP Testing Guide – OTG-CLIENT-004](https://owasp.org/www-project-web-security-testing-guide/)
