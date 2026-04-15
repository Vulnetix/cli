---
title: "VNX-PY-010 – SSL Certificate Verification Disabled in requests"
description: "Detect requests library calls that use verify=False, which disables TLS certificate validation and exposes HTTPS connections to man-in-the-middle attacks."
---

## Overview

This rule flags HTTP method calls on the `requests` library (`get`, `post`, `put`, `patch`, `delete`, `head`, `options`) that include `verify=False`. The `verify` parameter controls whether requests validates the server's TLS certificate against trusted Certificate Authorities. Setting it to `False` disables this validation entirely, meaning any server — including one presenting a self-signed, expired, or forged certificate — will be trusted. This makes HTTPS connections functionally equivalent to plain HTTP from a confidentiality and integrity perspective. This maps to [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html).

**Severity:** High | **CWE:** [CWE-295 – Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

## Why This Matters

TLS certificate validation is the mechanism that proves you are actually talking to the server you intended to reach. Without it, any network-adjacent attacker can intercept the connection, present their own certificate, and read or modify all traffic in both directions — a man-in-the-middle (MITM) attack. This matters most for:

- **Credentials and tokens** — login requests, API authentication headers, OAuth flows
- **Sensitive data** — health records, financial data, PII transmitted in request or response bodies
- **Webhooks and internal service calls** — an attacker on the internal network can impersonate internal services, poisoning data or issuing forged commands
- **Software download and update calls** — a MITM can replace a downloaded binary or configuration with a malicious version

The `verify=False` shortcut is often introduced as a temporary workaround for certificate problems (expired certs, self-signed internal CA, wrong hostname) and then forgotten. The underlying certificate problem needs to be fixed, not bypassed.

## What Gets Flagged

Any `requests.get/post/put/patch/delete/head/options` call with `verify=False` on the same line.

```python
# FLAGGED: SSL verification disabled on a GET request
response = requests.get("https://api.example.com/data", verify=False)

# FLAGGED: POST with credentials — credentials transmitted without protection
response = requests.post(
    "https://auth.internal/token",
    data={"username": user, "password": password},
    verify=False,
)

# FLAGGED: all HTTP methods are flagged
session.put("https://service.internal/update", json=payload, verify=False)
```

## Remediation

1. **Remove `verify=False` and fix the underlying certificate issue.** This is the correct long-term fix. If the request works after removing `verify=False`, the certificate is valid and no further action is needed.

2. **For internal services using a private CA, provide the CA bundle path.** Pass `verify` the path to your CA certificate or bundle instead of disabling verification entirely:

```python
import requests

# SAFE: verify against a specific CA certificate
response = requests.get(
    "https://internal.service.example",
    verify="/etc/ssl/certs/internal-ca.crt",
)

# SAFE: verify against a CA bundle file
response = requests.get(
    "https://internal.service.example",
    verify="/path/to/ca-bundle.crt",
)
```

3. **Use the `REQUESTS_CA_BUNDLE` environment variable for system-wide CA configuration.** This avoids hardcoding paths in code and allows the CA bundle path to be configured per environment:

```bash
export REQUESTS_CA_BUNDLE=/etc/ssl/certs/internal-ca.crt
```

```python
# SAFE: requests automatically uses REQUESTS_CA_BUNDLE if set
response = requests.get("https://internal.service.example")
```

4. **For mutual TLS (mTLS), use the `cert` parameter alongside proper `verify`.**

```python
# SAFE: mTLS with certificate verification enabled
response = requests.get(
    "https://api.example.com",
    cert=("/path/to/client.crt", "/path/to/client.key"),
    verify="/path/to/ca-bundle.crt",
)
```

5. **Use a `requests.Session` to set verification once for all calls in the session.** This prevents accidentally omitting the parameter on individual calls:

```python
import requests

session = requests.Session()
session.verify = "/etc/ssl/certs/ca-certificates.crt"

# All requests through this session use the configured CA bundle
response = session.get("https://api.example.com/data")
```

6. **Do not suppress the `InsecureRequestWarning`.** Some codebases call `urllib3.disable_warnings(InsecureRequestWarning)` alongside `verify=False` to silence console noise. Remove both — the warning is there to alert you that verification is disabled.

## References

- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)
- [OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
- [requests documentation – SSL Cert Verification](https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification)
- [Python docs – ssl module](https://docs.python.org/3/library/ssl.html)
- [CAPEC-94: Adversary in the Middle (AITM)](https://capec.mitre.org/data/definitions/94.html)
- [MITRE ATT&CK T1557 – Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)
