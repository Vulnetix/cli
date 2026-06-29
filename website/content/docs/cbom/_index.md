---
title: "CBOM"
weight: 8
description: "Discover cryptographic usage and emit a CycloneDX Cryptography Bill of Materials with post-quantum posture."
---

The `vulnetix cbom` command discovers cryptographic algorithms, certificates and crypto libraries used in a project — in **source code and configuration** — and produces a **Cryptography Bill of Materials (CBOM)** in CycloneDX format, classifying each algorithm for **post-quantum** posture.

> **This page is generated** from the detection catalog (`internal/cbom/catalog/*.json`). Run `just gen-cbom` after editing the catalog.

## What it detects

Four passes, all driven by a maintainable catalog:

- **Source code** — per-language crypto API usage (Go `crypto/*`, Python `hashlib`/pyca, Java JCA, Node `crypto`, …) plus generic call extractors. Algorithm spellings are case/separator-insensitive: `SHA256`, `Sha256`, `sha256` and `SHA_256` all resolve to one canonical SPDX algorithm.
- **Config** — TLS cipher suites & versions, SSH `Ciphers`/`KexAlgorithms`/`MACs`, JWT `alg`, OpenSSL/IPsec settings.
- **Certificates** — X.509 certificates and keys on disk (signature algorithm, key type & size, validity). Only metadata is read — never key bytes.
- **Dependencies** — declared crypto libraries (OpenSSL, Bouncy Castle, libsodium, liboqs, ring, Tink, pyca/cryptography, …).

## Post-quantum posture

Every algorithm is tagged `quantum-safe`, `quantum-vulnerable`, `deprecated` or `hybrid`, carries its CycloneDX `nistQuantumSecurityLevel` (0–6) and `classicalSecurityLevel`, and an annotated per-country approval matrix. Use `--fail-on quantum-vulnerable` (or `deprecated`) to gate CI.

The builtin catalog (version `2026.06.1`) covers **41 algorithms** and **12 crypto libraries**, including the NIST PQC standards (ML-KEM, ML-DSA, SLH-DSA), FN-DSA, HQC, FrodoKEM, Classic McEliece, LMS/HSS, XMSS, the regional KpqC selections (HAETAE, AIMer, SMAUG-T, NTRU+) and the de-facto hybrid groups (X25519MLKEM768, …).

{{< cards >}}
  {{< card link="algorithms" title="Algorithms" subtitle="Every algorithm the catalog detects and its PQC posture." icon="lock-closed" >}}
  {{< card link="standards-matrix" title="Standards Matrix" subtitle="Per-country approval status for PQC algorithms." icon="globe" >}}
  {{< card link="catalog-format" title="Catalog Format" subtitle="Extend or override detection with --catalog." icon="document-text" >}}
  {{< card link="../cli-reference/cbom" title="Command Reference" subtitle="vulnetix cbom flags and examples." icon="terminal" >}}
{{< /cards >}}
