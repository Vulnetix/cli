---
title: "VNX-GO-041 – Use of deprecated TLS version"
description: "Detect Go TLS configuration that sets MinVersion or MaxVersion to tls.VersionTLS10 or tls.VersionTLS11, enabling negotiation of deprecated protocol versions that are vulnerable to known attacks."
---

## Overview

This rule flags `tls.Config` struct literals or assignments where `MinVersion`, `MaxVersion`, or `Version` is set to `tls.VersionTLS10` or `tls.VersionTLS11`. Both TLS 1.0 and TLS 1.1 have been formally deprecated by the IETF (RFC 8996, March 2021) and are prohibited by PCI-DSS since June 2018. Allowing these versions permits negotiation of ciphersuites and protocol features that are vulnerable to POODLE, BEAST, CRIME, and other well-documented attacks. This maps to [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html).

Go's `crypto/tls` package defaults to `tls.VersionTLS12` as `MinVersion` since Go 1.18, but explicitly setting the minimum to an older version overrides this safe default and creates a regression that may go unnoticed in code review.

**Severity:** High | **CWE:** [CWE-326 – Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html) | **OWASP:** [A02:2021 – Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)

## Why This Matters

TLS 1.0 and TLS 1.1 rely on cipher constructions and negotiation mechanisms that are no longer considered safe. BEAST (Browser Exploit Against SSL/TLS) exploits a CBC-mode IV predictability issue in TLS 1.0 that allows session cookie decryption. POODLE (Padding Oracle On Downgraded Legacy Encryption) attacks SSLv3 but a variant affects TLS 1.0's CBC ciphersuites. Both attacks require an active network position (man-in-the-middle or on the same network segment), but coffee-shop Wi-Fi and cloud shared-tenancy environments make this a realistic threat model for web applications.

Beyond direct cryptographic attacks, TLS 1.0 and 1.1 lack support for secure cipher suites available in TLS 1.2 (AEAD ciphers such as AES-GCM and ChaCha20-Poly1305) and TLS 1.3 (which eliminates all non-AEAD options entirely). PCI-DSS 3.2 made TLS 1.2 the minimum mandatory version for all payment processing environments. Major browsers (Chrome, Firefox, Safari, Edge) have removed support for TLS 1.0 and 1.1. Continuing to allow these versions primarily serves legacy clients that represent a negligible fraction of modern traffic while materially increasing risk. MITRE ATT&CK T1068.003 covers exploitation of weakened cryptographic configurations.

## What Gets Flagged

The rule fires on `tls.Config` fields that reference deprecated version constants.

```go
// FLAGGED: MinVersion allows TLS 1.0 — BEAST and POODLE variant attacks possible
func createTLSConfig() *tls.Config {
    return &tls.Config{
        MinVersion: tls.VersionTLS10, // deprecated, RFC 8996
    }
}

// FLAGGED: explicit TLS 1.1 minimum
func serverConfig() *tls.Config {
    cfg := &tls.Config{}
    cfg.MinVersion = tls.VersionTLS11
    return cfg
}

// FLAGGED: MaxVersion capped at TLS 1.1 prevents TLS 1.2/1.3 negotiation
func legacyClientConfig() *tls.Config {
    return &tls.Config{
        MaxVersion: tls.VersionTLS11,
    }
}
```

```go
// SAFE: TLS 1.2 minimum with preferred TLS 1.3
func createTLSConfig(certFile, keyFile string) (*tls.Config, error) {
    cert, err := tls.LoadX509KeyPair(certFile, keyFile)
    if err != nil {
        return nil, err
    }
    return &tls.Config{
        MinVersion:   tls.VersionTLS12, // RFC 8996 compliant minimum
        Certificates: []tls.Certificate{cert},
        CipherSuites: []uint16{
            tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        },
    }, nil
}
```

## Remediation

1. **Set `MinVersion: tls.VersionTLS12`** in all `tls.Config` structs for both servers and clients. This is already the Go default since 1.18, but any explicit `MinVersion` assignment must be updated to avoid overriding the safe default.

   ```go
   // SAFE: explicit TLS 1.2 minimum, TLS 1.3 preferred automatically
   func newTLSConfig() *tls.Config {
       return &tls.Config{
           MinVersion: tls.VersionTLS12,
           // Go's crypto/tls negotiates TLS 1.3 automatically when both
           // sides support it — no explicit MaxVersion needed.
       }
   }
   ```

2. **Prefer TLS 1.3 only (`MinVersion: tls.VersionTLS13`)** for internal services and APIs where all clients are under your control. TLS 1.3 eliminates weak cipher suites entirely, mandates forward secrecy, and reduces handshake round-trips.

   ```go
   // SAFE: TLS 1.3 only for internal microservice communication
   func internalServiceTLSConfig() *tls.Config {
       return &tls.Config{
           MinVersion: tls.VersionTLS13,
       }
   }
   ```

3. **Audit all `http.Server`, `http.Transport`, `grpc.ServerOption`, and `net.Listener` usages** to ensure no `tls.Config` is instantiated without an explicit `MinVersion` or with a deprecated version constant. Centralise TLS configuration in a shared package to enforce consistent settings.

4. **Test TLS configuration** with `go test` using `crypto/tls` test helpers, or with external tools such as `testssl.sh` or Qualys SSL Labs, to verify that TLS 1.0 and 1.1 are not negotiated in production.

## References

- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
- [RFC 8996 – Deprecating TLS 1.0 and TLS 1.1](https://datatracker.ietf.org/doc/html/rfc8996)
- [OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
- [CAPEC-63: Simple Script Injection](https://capec.mitre.org/data/definitions/63.html)
- [MITRE ATT&CK T1068 – Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [PCI-DSS v3.2 – Migration from SSL and Early TLS](https://www.pcisecuritystandards.org/documents/Migrating-from-SSL-Early-TLS-Info-Supp-v1_1.pdf)
- [Go crypto/tls package documentation](https://pkg.go.dev/crypto/tls)
