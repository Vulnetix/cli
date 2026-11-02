---
title: "Standards Matrix"
weight: 2
description: "Per-country/body approval status for each algorithm in the catalog."
---

Approval status per standards body, drawn from published post-quantum guidance. An empty cell means the body has not specified a status for that algorithm in the catalog.

> Generated from the catalog. Edit `internal/cbom/catalog/algorithms.json` and run `just gen-cbom`.

| Algorithm | ACSC | AIVD | BSI | CCCS | CNSA 2.0 | KpqC | NCSC | NIST | NUKIB |
|-----------|------|------|------|------|------|------|------|------|------|
| AES | - | - | - | - | - | - | - | approved | - |
| AIMer | - | - | - | - | - | selected | - | - | - |
| Classic McEliece | - | accepted | recommended | - | - | - | - | - | approved |
| DES | - | - | - | - | - | - | - | disallowed | - |
| DSA | - | - | - | - | - | - | - | deprecated | - |
| ECDSA | - | - | - | - | disallowed | - | - | deprecated | - |
| FN-DSA (Falcon) | - | accepted | - | - | - | - | - | selected | - |
| FrodoKEM | - | accepted | recommended | - | - | - | - | - | approved |
| HAETAE | - | - | - | - | - | selected | - | - | - |
| HQC | - | - | - | - | - | - | - | selected | - |
| LMS/HSS | - | - | recommended | - | approved | - | - | approved | - |
| MD5 | - | - | - | - | - | - | - | disallowed | - |
| ML-DSA-65 | approved | - | recommended | - | - | - | approved | approved | - |
| ML-DSA-87 | approved | recommended | recommended | - | approved | - | - | approved | - |
| ML-KEM-1024 | - | recommended | recommended | - | approved | - | - | approved | approved |
| ML-KEM-512 | approved | - | recommended | approved | - | - | - | approved | - |
| ML-KEM-768 | approved | accepted | recommended | - | - | - | approved | approved | - |
| NTRU+ | - | - | - | - | - | selected | - | - | - |
| RSA | - | - | transitional | - | disallowed | - | - | deprecated | - |
| SHA-1 | - | - | - | - | - | - | - | disallowed | - |
| SHA-256 | - | - | - | - | - | - | - | approved | - |
| SLH-DSA | - | recommended | recommended | approved | - | - | - | approved | - |
| SMAUG-T | - | - | - | - | - | selected | - | - | - |
| Triple DES | - | - | - | - | - | - | - | deprecated | - |
| X25519MLKEM768 | - | - | recommended | - | - | - | - | allowed | - |
| XMSS/XMSSMT | - | - | recommended | - | approved | - | - | approved | - |
