---
title: "VNX-GO-011 – Go gob Deserialization from HTTP Request Body"
description: "Detect Go code that decodes gob data directly from an HTTP request body, which can cause denial of service or trigger unexpected behaviour in complex types."
---

## Overview

This rule flags Go code where `gob.NewDecoder` receives an HTTP request body (`r.Body`, `req.Body`, `request.Body`) as its input. The `encoding/gob` format is designed for inter-process communication between trusted Go programs — it was never intended to parse data from untrusted network sources. Gob can instantiate any exported Go type registered via `gob.Register()`, and malformed or maliciously crafted gob streams can trigger excessive memory allocation, stack overflows during recursive type decoding, or unexpected behaviour when complex interface types are hydrated. This maps to [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html).

**Severity:** Medium | **CWE:** [CWE-502 – Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html) | **OWASP ASVS:** [V5.5 – Deserialization Prevention](https://owasp.org/www-project-application-security-verification-standard/)

> **Go idiom note:** Using `encoding/json` with `io.LimitReader` for HTTP request bodies IS the idiomatic Go default for public-facing APIs. Using `encoding/gob` to decode untrusted network input is NOT idiomatic and requires explicit justification. The secure approach — JSON with a size limit — is the standard Go HTTP handler pattern.

## Why This Matters

Unlike JSON or Protocol Buffers, gob encodes full Go type information in the stream. A crafted gob payload can force the decoder to allocate very large slices, deeply nested maps, or recursive pointer structures that exhaust available memory or stack space. Because the Go runtime doesn't impose a default decode-size limit, a single malicious request can take down the entire process. Gob also silently populates unexported fields and interface values in ways that may violate application invariants, potentially leading to logic bugs or authorization bypasses.

OWASP ASVS v4.0 requirement **V5.5.3** prohibits deserialization of untrusted data using formats that can instantiate arbitrary object types. Gob's type registration mechanism (`gob.Register`) creates exactly this risk when parsing untrusted input. MITRE ATT&CK T1190 (Exploit Public-Facing Application) covers remote exploitation through malicious serialized payloads.

Neither `go vet` nor `staticcheck` detect this pattern directly — it requires semantic analysis of the data source feeding the decoder, making this a valuable additional check.

## What Gets Flagged

The rule fires when `gob.NewDecoder` appears on the same line as an HTTP request body reference (`r.Body`, `req.Body`, `request.Body`).

```go
// FLAGGED: gob decoding directly from untrusted HTTP request body
func handler(w http.ResponseWriter, r *http.Request) {
    var msg Message
    gob.NewDecoder(r.Body).Decode(&msg) // DoS via crafted gob payload
}

// FLAGGED: storing decoder from request body
func handler(w http.ResponseWriter, r *http.Request) {
    dec := gob.NewDecoder(r.Body)
    dec.Decode(&payload) // no size limit, no type safety
}
```

## Remediation

1. **Use JSON or Protocol Buffers for HTTP APIs.** These formats have well-understood parsing boundaries and don't instantiate arbitrary types. This is the idiomatic Go approach for public-facing HTTP handlers:

```go
// SAFE: JSON decoding with explicit struct type and size limit
import (
    "encoding/json"
    "io"
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    var msg Message
    r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB limit enforced by net/http
    dec := json.NewDecoder(r.Body)
    dec.DisallowUnknownFields() // reject unexpected fields
    if err := dec.Decode(&msg); err != nil {
        http.Error(w, "bad request", http.StatusBadRequest)
        return
    }
}
```

2. **If gob is necessary for a specific use case, limit the input size.** Wrap the reader in `io.LimitReader` or `http.MaxBytesReader` to cap memory consumption before any decoding begins:

```go
// SAFER: size-limited gob decoding (only for trusted internal endpoints)
func handler(w http.ResponseWriter, r *http.Request) {
    limited := io.LimitReader(r.Body, 1<<20) // 1 MiB max
    var msg Message
    if err := gob.NewDecoder(limited).Decode(&msg); err != nil {
        http.Error(w, "bad request", http.StatusBadRequest)
        return
    }
}
```

3. **Reserve gob for trusted internal RPC.** Gob is appropriate for communication between services you control on a private network — not for public-facing HTTP endpoints. If you need efficient binary serialisation for internal services, consider `encoding/gob` only over mutually-authenticated TLS connections, or prefer Protocol Buffers (`google.golang.org/protobuf`) which have well-specified size limits and schema enforcement.

## References

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [OWASP Application Security Verification Standard v4.0 – V5.5 Deserialization Prevention](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [OWASP Go Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Go_Security_Cheat_Sheet.html)
- [Go encoding/gob package documentation](https://pkg.go.dev/encoding/gob)
- [Go io.LimitReader documentation](https://pkg.go.dev/io#LimitReader)
- [Go http.MaxBytesReader documentation](https://pkg.go.dev/net/http#MaxBytesReader)
- [CAPEC-586: Object Injection](https://capec.mitre.org/data/definitions/586.html)
- [MITRE ATT&CK T1190 – Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
