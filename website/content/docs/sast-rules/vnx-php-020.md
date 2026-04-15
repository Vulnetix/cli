---
title: "VNX-PHP-020 – PHP curl SSL certificate verification disabled"
description: "Detects CURLOPT_SSL_VERIFYPEER or CURLOPT_SSL_VERIFYHOST set to false or 0 in PHP curl requests, which disables TLS certificate validation and enables man-in-the-middle attacks."
---

## Overview

This rule detects PHP `curl_setopt()` calls that set `CURLOPT_SSL_VERIFYPEER` to `false` (or `0`) or `CURLOPT_SSL_VERIFYHOST` to `false` (or `0`). These options control whether PHP's curl extension validates the TLS certificate presented by the remote server. When they are disabled, curl will accept any certificate — including self-signed, expired, or attacker-issued certificates — and complete the TLS handshake without verifying the server's identity.

`CURLOPT_SSL_VERIFYPEER` controls whether the server's certificate chain is validated against trusted Certificate Authorities. `CURLOPT_SSL_VERIFYHOST` controls whether the certificate's Common Name (CN) or Subject Alternative Names (SANs) match the hostname being connected to. Disabling either removes a critical layer of the TLS security model: the assurance that you are communicating with the intended server and not an impostor.

Both options are frequently disabled as a shortcut when working with self-signed certificates in development or staging environments and then accidentally committed to production code. Some code is copied from Stack Overflow answers that disable verification "for testing" without recognising the security implications.

**Severity:** High | **CWE:** [CWE-295 – Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

## Why This Matters

Disabling TLS certificate validation makes HTTPS equivalent to HTTP from a security perspective. A network attacker — anyone who can intercept traffic between the PHP server and the remote endpoint — can present a fake certificate and conduct a full man-in-the-middle attack. They read all data sent and received, modify requests and responses in transit, and inject malicious content without detection.

In API integration contexts, this means an attacker can intercept authentication tokens, API keys sent in headers, payment card data, health records, or any other sensitive information transmitted in the request or response. The attack is silent — the PHP application receives a normal-looking response and has no indication anything is wrong.

In cloud environments where PHP servers make calls to internal services, secrets management endpoints, or metadata APIs, a compromised network path combined with disabled certificate verification creates significant privilege escalation opportunities.

## What Gets Flagged

```php
// FLAGGED: certificate chain verification disabled
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

// FLAGGED: hostname verification disabled
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);

// FLAGGED: combined — both checks bypassed
curl_setopt_array($ch, [
    CURLOPT_SSL_VERIFYPEER => false,
    CURLOPT_SSL_VERIFYHOST => 0,
]);
```

## Remediation

1. **Remove `CURLOPT_SSL_VERIFYPEER` and `CURLOPT_SSL_VERIFYHOST` overrides entirely** — the default values (`true` and `2` respectively) are correct and secure.

2. **For self-signed certificates in development or internal services**, use `CURLOPT_CAINFO` to specify the path to a custom CA bundle that includes the self-signed root, rather than disabling verification.

3. **Ensure the system CA bundle is up to date** on the PHP server — outdated CA bundles can cause legitimate certificate validation failures.

4. **Use `CURLOPT_CAPATH`** to specify a directory of CA certificates if individual file specification is not practical.

```php
<?php
// SAFE: secure defaults (no VERIFYPEER/VERIFYHOST override)
$ch = curl_init('https://api.example.com/data');
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT        => 10,
    // CURLOPT_SSL_VERIFYPEER defaults to true — do not override
    // CURLOPT_SSL_VERIFYHOST defaults to 2 — do not override
]);
$response = curl_exec($ch);

// SAFE: internal service with self-signed cert — use CAINFO instead of disabling
$ch = curl_init('https://internal-service.corp/api');
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_CAINFO         => '/etc/ssl/certs/internal-ca.crt', // custom CA
    // VERIFYPEER and VERIFYHOST remain enabled
]);
```

## References

- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)
- [CAPEC-94: Man in the Middle Attack](https://capec.mitre.org/data/definitions/94.html)
- [OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [PHP Manual – curl_setopt() SSL options](https://www.php.net/manual/en/function.curl-setopt.php)
- [cURL documentation – SSL / TLS options](https://curl.se/docs/sslcerts.html)
