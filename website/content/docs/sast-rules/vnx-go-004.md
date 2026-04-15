---
title: "VNX-GO-004 – TLS InsecureSkipVerify Enabled"
description: "Detect Go TLS configurations that set InsecureSkipVerify to true, disabling certificate validation and enabling man-in-the-middle attacks."
---

## Overview

This rule flags any Go source file that sets `InsecureSkipVerify: true` inside a `tls.Config` struct. When this flag is enabled the TLS stack accepts any certificate — expired, self-signed, issued by an untrusted authority, or one belonging to a completely different host — without complaint. This removes the authentication guarantee that TLS is designed to provide and makes every HTTPS connection your application initiates trivially interceptable. The vulnerability maps to [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html).

**Severity:** High | **CWE:** [CWE-295 – Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

## Why This Matters

TLS serves two purposes: encrypting traffic in transit and authenticating the remote endpoint. `InsecureSkipVerify` disables the second. An attacker on the same network — a shared Wi-Fi, a cloud VPC, a compromised router — can present a fake certificate and intercept all traffic your application sends or receives. This is a man-in-the-middle attack (MITRE ATT&CK T1557). In practice this means API keys, session tokens, database credentials, and user data transmitted over what appears to be a secure HTTPS connection are fully visible to the attacker. The pattern commonly appears when developers work around certificate issues during development and the flag accidentally ships to production.

## What Gets Flagged

The rule matches any Go line containing `InsecureSkipVerify` set to `true`. This covers direct struct literals and assignments to the field.

```go
// FLAGGED: certificate validation completely disabled
tr := &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}
client := &http.Client{Transport: tr}
resp, err := client.Get("https://internal-api.example.com/data")
```

```go
// FLAGGED: also matches assignment form
cfg := &tls.Config{}
cfg.InsecureSkipVerify = true
```

## Remediation

1. **Remove `InsecureSkipVerify: true` entirely.** The Go TLS stack validates certificates correctly by default. Simply removing the field (or setting it to `false`) restores full certificate verification with no other changes required.

```go
// SAFE: default TLS configuration with certificate validation enabled
client := &http.Client{}
resp, err := client.Get("https://internal-api.example.com/data")
```

2. **Trust additional Certificate Authorities without disabling verification.** If you need to trust a private CA (e.g., an internal PKI for service-to-service communication), load its certificate into a custom `tls.Config` rather than disabling verification:

```go
// SAFE: trust a private CA while keeping certificate validation intact
import (
    "crypto/tls"
    "crypto/x509"
    "os"
)

func tlsConfigWithPrivateCA(caPath string) (*tls.Config, error) {
    caCert, err := os.ReadFile(caPath)
    if err != nil {
        return nil, err
    }
    pool := x509.NewCertPool()
    if !pool.AppendCertsFromPEM(caCert) {
        return nil, fmt.Errorf("failed to parse CA certificate")
    }
    return &tls.Config{RootCAs: pool}, nil
}
```

3. **Use `InsecureSkipVerify` only in isolated test environments with a test-only build tag.** If you absolutely need to skip verification in a local integration test, gate it behind a build tag so it can never reach production code.

```go
//go:build integration_test

package mypackage

import "crypto/tls"

func testTLSConfig() *tls.Config {
    return &tls.Config{InsecureSkipVerify: true} // test-only, never in production
}
```

4. **Fix the underlying certificate issue.** If `InsecureSkipVerify` was added to work around a certificate error, fix the root cause: renew expired certificates, install the correct CA bundle, or configure the server with a valid certificate from a trusted CA.

## References

- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)
- [OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
- [Go crypto/tls package documentation](https://pkg.go.dev/crypto/tls)
- [Go crypto/x509 package documentation](https://pkg.go.dev/crypto/x509)
- [CAPEC-94: Adversary in the Middle (MITM)](https://capec.mitre.org/data/definitions/94.html)
- [MITRE ATT&CK T1557 – Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)
