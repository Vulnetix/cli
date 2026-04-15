---
title: "VNX-PY-021 – Weak or Deprecated SSL/TLS Protocol Version"
description: "Detect Python code that references deprecated SSL/TLS protocol constants (SSLv2, SSLv3, TLSv1, TLSv1.1), which have documented cryptographic weaknesses and are rejected by modern servers."
---

## Overview

This rule detects Python code that uses deprecated SSL/TLS protocol version constants: `PROTOCOL_SSLv2`, `PROTOCOL_SSLv3`, `PROTOCOL_TLSv1`, `PROTOCOL_TLSv1_1`, `SSLv2_METHOD`, `SSLv3_METHOD`, `TLSv1_METHOD`, or `TLSv1_1_METHOD`. These constants select specific legacy protocol versions that have been cryptographically broken and officially deprecated. Using them means your application will negotiate a weak protocol even when the remote server supports modern alternatives.

SSLv2 and SSLv3 were deprecated decades ago: SSLv3 is vulnerable to the POODLE attack (2014) and DROWN, while SSLv2 has been considered insecure since the 1990s. TLS 1.0 is vulnerable to BEAST and has weaknesses in its padding oracle handling; TLS 1.1 improves on this but lacks the AEAD cipher suites required for strong security. The IETF formally deprecated TLS 1.0 and 1.1 in RFC 8996 (2021). Most major browsers, CDNs, and servers have disabled support for these versions.

The correct approach is to use `ssl.PROTOCOL_TLS_CLIENT` (for clients) or `ssl.PROTOCOL_TLS_SERVER` (for servers), set `context.minimum_version = ssl.TLSVersion.TLSv1_2`, and let Python negotiate the best mutually supported version with the peer. This ensures TLS 1.3 is used when available while maintaining backward compatibility with servers that only support TLS 1.2.

**Severity:** High | **CWE:** [CWE-326 – Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)

## Why This Matters

Exploiting weak TLS versions is a well-studied attack technique. The POODLE attack against SSLv3 allows a network attacker to decrypt encrypted HTTP cookies in approximately 256 requests by exploiting padding oracle behavior in CBC mode. BEAST (TLS 1.0) enables a chosen-plaintext attack against HTTPS sessions. In practice, these attacks require an attacker who can observe network traffic — a realistic assumption on shared Wi-Fi networks, corporate proxies, and cloud environments with misconfigured network policies.

Beyond active exploitation, applications that negotiate TLS 1.0 or 1.1 fail PCI DSS compliance scans (Requirement 4.2.1 mandates TLS 1.2 minimum) and FIPS 140-2/140-3 validations. Major payment processors, healthcare APIs, and government services now refuse TLS 1.0/1.1 connections entirely, meaning this is also a reliability issue: code using deprecated constants will simply fail to connect.

Python itself removed or restricted several of these constants across versions (e.g., `PROTOCOL_SSLv2` was removed in Python 3.10, `PROTOCOL_SSLv3` in 3.6), so code using them may also raise `AttributeError` at runtime on modern Python.

## What Gets Flagged

```python
import ssl

# FLAGGED: TLS 1.0 protocol constant
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)

# FLAGGED: TLS 1.1 protocol constant
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)

# FLAGGED: SSLv3 (broken)
context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)

# FLAGGED: SSLv2 (critically broken)
context = ssl.SSLContext(ssl.PROTOCOL_SSLv2)

# FLAGGED: OpenSSL-style method constants via pyOpenSSL
from OpenSSL.SSL import TLSv1_METHOD, Context
ctx = Context(TLSv1_METHOD)

# FLAGGED: via string matching on TLSv1_METHOD
ctx = Context(ssl.SSLv3_METHOD)
```

The rule applies only to `.py` files and matches all eight deprecated constant names.

## Remediation

1. Use `ssl.PROTOCOL_TLS_CLIENT` or `ssl.PROTOCOL_TLS_SERVER` and set a minimum version.
2. Set `context.minimum_version = ssl.TLSVersion.TLSv1_2` as a floor; prefer `TLSv1_3` where possible.
3. Enable `context.check_hostname = True` and `context.verify_mode = ssl.CERT_REQUIRED` (these are the defaults for `PROTOCOL_TLS_CLIENT`).

```python
import ssl
import urllib.request

# SAFE: modern TLS client context with TLS 1.2 minimum
def create_tls_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # check_hostname and CERT_REQUIRED are on by default for PROTOCOL_TLS_CLIENT
    return context

# SAFE: using the default context (recommended for most cases)
def fetch_url(url: str) -> bytes:
    context = ssl.create_default_context()
    # create_default_context() sets minimum_version to TLSv1_2 in Python 3.10+
    with urllib.request.urlopen(url, context=context) as response:
        return response.read()

# SAFE: server-side TLS context
def create_server_context(certfile: str, keyfile: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return context

# SAFE: explicit TLS 1.3 minimum for high-security endpoints
def create_strict_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    return context
```

## References

- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
- [Python ssl Module Documentation](https://docs.python.org/3/library/ssl.html)
- [OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
- [OWASP Python Security Project](https://owasp.org/www-project-python-security/)
- [RFC 8996 – Deprecating TLS 1.0 and TLS 1.1](https://datatracker.ietf.org/doc/html/rfc8996)
- [POODLE Attack (CVE-2014-3566)](https://www.openssl.org/~bodo/ssl-poodle.pdf)
- [CAPEC-217: Exploiting Incorrectly Configured SSL/TLS](https://capec.mitre.org/data/definitions/217.html)
