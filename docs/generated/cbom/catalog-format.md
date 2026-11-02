---
title: "Catalog Format"
weight: 3
description: "The CBOM detection catalog schema, and how to extend or override it with --catalog."
---

All CBOM detection is driven by a declarative catalog so it can be maintained over time without code changes. The builtin catalog is embedded in the binary (`internal/cbom/catalog/*.json`). You can extend or replace it at runtime:

```bash
vulnetix cbom --catalog ./my-algos.json          # merge over the builtin (override by id)
vulnetix cbom --catalog ./only.json --no-builtin-catalog   # replace entirely
```

A catalog file is JSON with any of three top-level keys: `algorithms`, `libraries`, `call_extractors`.

## Algorithm entry

```jsonc
{
  "id": "sha-256",                       // canonical SPDX id (override key)
  "name": "SHA-256",                     // canonical stored name
  "spdx_class": "Cryptographic-Hash-Function/Hash-Function",
  "oid": "2.16.840.1.101.3.4.2.1",
  "aliases": ["sha256", "sha_256", "sha2-256"],   // matched case/separator-insensitively
  "primitive": "hash",                   // CycloneDX algorithmProperties.primitive enum
  "crypto_functions": ["digest"],        // CycloneDX cryptoFunctions enum
  "classical_security_level": 128,
  "nist_quantum_security_level": 2,      // 0..6 (0 = not quantum-safe)
  "pqc_status": "quantum-safe",          // quantum-safe | quantum-vulnerable | deprecated | hybrid
  "standards": {"NIST": "approved", "BSI": "approved"},   // per-country matrix
  "source_patterns": {                   // language -> Go RE2 patterns (attribute this algorithm)
    "go": ["crypto/sha256"],
    "python": ["(?i)hashlib\\.sha256"]
  },
  "config_patterns": ["(?i)\\bSHA[_-]?256\\b"]   // matched in TLS/SSH/JWT/OpenSSL config
}
```

The `primitive`, `crypto_functions`, `mode`, `padding` and `pqc_status` values are validated against the CycloneDX enums at load time and by `just gen-cbom`.

## Library entry

```jsonc
{
  "id": "liboqs",
  "name": "liboqs",
  "provider": "Open Quantum Safe",
  "languages": ["c", "cpp", "python", "go", "rust"],
  "purl_names": {"generic": "liboqs"},
  "import_patterns": ["#include\\s*<oqs/", "(?i)\\bOQS_(?:KEM|SIG)_"]
}
```

## Call extractor

A call extractor captures an algorithm token from a generic crypto API; the token is normalized and resolved through the alias index, so arbitrary spellings map to one algorithm.

```jsonc
{"languages": ["javascript"], "pattern": "(?i)createHash\\(\\s*['\"]([\\w./-]+)['\"]", "role": "algorithm"}
// role: "algorithm" | "transform" (Java AES/CBC/PKCS5Padding) | "jwt" ("alg":"…")
```

Each extractor pattern must have **exactly one capture group**. All patterns are Go RE2 (no backreferences/lookaround).
