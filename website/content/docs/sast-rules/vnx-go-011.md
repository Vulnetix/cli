---
title: "VNX-GO-011 – Go gob Deserialization from HTTP Request Body"
description: "Detect Go code that decodes gob data directly from an HTTP request body, which can cause denial of service or trigger unexpected behaviour in complex types."
---

## Overview

This rule flags Go code where `gob.NewDecoder` receives an HTTP request body (`r.Body`, `req.Body`, `request.Body`) as its input. The `encoding/gob` format is designed for inter-process communication between trusted Go programs — it was never intended to parse data from untrusted network sources. Gob can instantiate any exported Go type registered via `gob.Register()`, and malformed or maliciously crafted gob streams can trigger excessive memory allocation, stack overflows during recursive type decoding, or unexpected behaviour when complex interface types are hydrated. This maps to [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html).

**Severity:** Medium | **CWE:** [CWE-502 – Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

## Why This Matters

Unlike JSON or Protocol Buffers, gob encodes full Go type information in the stream. A crafted gob payload can force the decoder to allocate very large slices, deeply nested maps, or recursive pointer structures that exhaust available memory or stack space. Because the Go runtime doesn't impose a default decode-size limit, a single malicious request can take down the entire process. Gob also silently populates unexported fields and interface values in ways that may violate application invariants, potentially leading to logic bugs or authorization bypasses.

## What Gets Flagged

The rule fires when `gob.NewDecoder` appears on the same line as an HTTP request body reference (`r.Body`, `req.Body`, `request.Body`).

```go
// FLAGGED: gob decoding directly from untrusted HTTP request body
func handler(w http.ResponseWriter, r *http.Request) {
    var msg Message
    gob.NewDecoder(r.Body).Decode(&msg) // DoS via crafted gob payload
}
```

## Remediation

1. **Use JSON or Protocol Buffers for HTTP APIs.** These formats have well-understood parsing boundaries and don't instantiate arbitrary types:

```go
// SAFE: JSON decoding with explicit struct type and size limit
func handler(w http.ResponseWriter, r *http.Request) {
    var msg Message
    if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&msg); err != nil {
        http.Error(w, "bad request", http.StatusBadRequest)
        return
    }
}
```

2. **If gob is necessary, limit the input size.** Wrap the reader in `io.LimitReader` to cap memory consumption:

```go
// SAFER: size-limited gob decoding
func handler(w http.ResponseWriter, r *http.Request) {
    limited := io.LimitReader(r.Body, 1<<20) // 1 MiB max
    var msg Message
    if err := gob.NewDecoder(limited).Decode(&msg); err != nil {
        http.Error(w, "bad request", http.StatusBadRequest)
        return
    }
}
```

3. **Reserve gob for trusted internal RPC.** Gob is appropriate for communication between services you control on a private network — not for public-facing HTTP endpoints.

## References

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [Go encoding/gob package documentation](https://pkg.go.dev/encoding/gob)
- [Go io.LimitReader documentation](https://pkg.go.dev/io#LimitReader)
- [CAPEC-586: Object Injection](https://capec.mitre.org/data/definitions/586.html)
- [MITRE ATT&CK T1190 – Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
