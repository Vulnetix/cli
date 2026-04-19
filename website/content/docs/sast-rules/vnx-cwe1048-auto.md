---
title: "VNX-1048 – Sensitive Data in Referrer"
description: "Detects outbound HTTP client patterns across Go, Java, Node.js, PHP, and Python that may expose sensitive data through Referer headers or query strings in GET requests."
---

## Overview

VNX-1048 is an auto-generated broad-pattern rule that searches for HTTP client request patterns across Go, Java, Node.js, PHP, and Python source files. The rule targets `http.NewRequest` in Go, `HttpURLConnection` in Java, `fetch` in Node.js, `curl` in PHP, and `requests.get` in Python. These are associated with [CWE-1048](https://cwe.mitre.org/data/definitions/1048.html) in the rule metadata.

Note: CWE-1048 in MITRE's catalog covers "Invokable Control Element with Large Number of Outward Calls." The vulnerability this rule detects — information exposure through Referer headers and GET query strings — maps to [CWE-598: Use of GET Request Method with Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html) and [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html). The CWE mapping is a known limitation of this auto-generated rule.

All flagged patterns are standard HTTP client APIs; findings require manual review to determine whether sensitive data such as tokens, session IDs, or personal information is transmitted in URLs or headers that may be logged or leaked.

**Severity:** Medium | **CWE:** [CWE-1048](https://cwe.mitre.org/data/definitions/1048.html) | **OWASP:** [A02:2021 – Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)

## Why This Matters

Sensitive data placed in URL query strings is captured in browser history, server access logs, proxy logs, and the HTTP `Referer` header sent to third-party resources. Tokens, API keys, passwords, and personal identifiers passed as GET parameters can leak through any of these channels without the application's knowledge.

Similarly, applications that make outbound HTTP requests with secrets embedded in URLs — webhook callbacks, third-party API calls — expose those secrets to the infrastructure handling those requests, including intermediary proxies and CDNs.

## What Gets Flagged

The rule scans Go, Java, Node.js, PHP, and Python source files for outbound HTTP client patterns:

```python
# FLAGGED: Python requests.get with token in URL
import requests
requests.get(f"https://api.example.com/data?token={secret_token}")
```

```javascript
// FLAGGED: Node.js fetch — review for query string secrets
fetch(`https://api.example.com/notify?key=${apiKey}&user=${userId}`)
```

```go
// FLAGGED: Go http.NewRequest — confirm no secrets in URL
req, _ := http.NewRequest("GET", "https://api.example.com/query?auth="+token, nil)
```

## Remediation

1. Never place secrets, tokens, session IDs, or personal data in URL query strings. Use request headers (e.g., `Authorization: Bearer <token>`) instead.
2. Use POST with a request body for any operation that transmits sensitive data, so the payload is not recorded in access logs.
3. Audit outbound HTTP calls for secrets embedded in the URL path or query parameters.
4. Configure your HTTP client to suppress the `Referer` header when making requests to third-party services, or set `Referrer-Policy: no-referrer` in browser contexts.
5. Rotate any credentials that may have been logged in server access logs as a result of GET-based transmission.

## References

- [CWE-598: Use of GET Request Method with Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [OWASP Testing for Sensitive Information in HTTP Referrer Header](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
