---
title: "VNX-1047 – SSRF without Timeout"
description: "Detects outbound HTTP request patterns across Go, Java, Node.js, PHP, and Python that may be vulnerable to Server-Side Request Forgery when request targets are derived from user input."
---

## Overview

VNX-1047 is an auto-generated broad-pattern rule that searches for outbound HTTP request primitives across Go, Java, Node.js, PHP, and Python source files. The rule targets `http.Get` in Go, `URLConnection` in Java, `http.request` in Node.js, `file_get_contents` in PHP, and `urllib` in Python. These are associated with [CWE-1047](https://cwe.mitre.org/data/definitions/1047.html) in the rule metadata.

Note: CWE-1047 in MITRE's catalog covers "Modules with Circular Dependencies." The vulnerability this rule detects — Server-Side Request Forgery — maps to [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html). The CWE mapping is a known limitation of this auto-generated rule.

The rule name "SSRF without Timeout" also highlights a secondary risk: HTTP requests without enforced timeouts enable slowloris-style denial of service where hanging connections exhaust server resources.

**Severity:** Medium | **CWE:** [CWE-1047](https://cwe.mitre.org/data/definitions/1047.html) | **OWASP:** [A10:2021 – Server-Side Request Forgery](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)

## Why This Matters

SSRF enables attackers to use the application server as a proxy to reach internal services that are not directly accessible from the internet — cloud metadata endpoints (e.g., `http://169.254.169.254/`), internal databases, Kubernetes API servers, and other infrastructure. In cloud environments this commonly leads to credential theft from instance metadata services and full account compromise.

Outbound requests without timeouts are exploited to cause denial-of-service by opening large numbers of slow or stalled connections, exhausting connection pools, file descriptors, or goroutine/thread budgets.

## What Gets Flagged

The rule scans Go, Java, Node.js, PHP, and Python source files for outbound HTTP request patterns:

```python
# FLAGGED: Python urllib with user-controlled URL
import urllib.request
response = urllib.request.urlopen(request.form['webhook_url'])
```

```go
// FLAGGED: Go http.Get without timeout
resp, err := http.Get(userSuppliedURL)
```

```php
// FLAGGED: PHP file_get_contents with external URL
$data = file_get_contents($_POST['feed_url']);
```

## Remediation

1. Validate all user-supplied URLs against a strict allowlist of permitted schemes (`https` only), hostnames, and port ranges.
2. Resolve the destination hostname to an IP address and reject requests to private RFC-1918 ranges, loopback addresses, and link-local addresses (including `169.254.169.254`).
3. Always configure explicit connection and read timeouts:
   - **Go**: use `http.Client{Timeout: 10 * time.Second}` instead of the default client.
   - **Python**: `urllib.request.urlopen(url, timeout=10)` or `requests.get(url, timeout=10)`.
   - **Node.js**: set `timeout` on the request options object.
4. Disable automatic redirect following, or limit redirects and re-validate the destination after each hop.
5. Consider routing all outbound requests through an egress proxy that enforces allowlists at the network level.

## References

- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP Top 10 A10:2021 – SSRF](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
- [PortSwigger: SSRF](https://portswigger.net/web-security/ssrf)
