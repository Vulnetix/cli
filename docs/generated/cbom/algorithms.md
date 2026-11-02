---
title: "Algorithms"
weight: 1
description: "Every cryptographic algorithm the CBOM detector recognises, with its post-quantum posture."
---

Each algorithm below maps to a CycloneDX `cryptographic-asset` component. Aliases are matched case/separator-insensitively and stored under the canonical SPDX name.

> Generated from the catalog. To add or refine an algorithm, edit `internal/cbom/catalog/algorithms.json` and run `just gen-cbom`.

| Algorithm | Primitive | PQC Status | Q-Level | Classical | OID |
|-----------|-----------|------------|---------|-----------|-----|
| DES | `block-cipher` | deprecated | 0 | 56 | - |
| MD5 | `hash` | deprecated | 0 | - | `1.2.840.113549.2.5` |
| RC4 | `stream-cipher` | deprecated | 0 | - | - |
| SHA-1 | `hash` | deprecated | 0 | - | `1.3.14.3.2.26` |
| Triple DES | `block-cipher` | deprecated | 0 | 112 | `1.2.840.113549.3.7` |
| SecP256r1MLKEM768 | `kem` | hybrid | 3 | - | - |
| SecP384r1MLKEM1024 | `kem` | hybrid | 5 | - | - |
| X25519MLKEM768 | `kem` | hybrid | 3 | - | - |
| AES | `block-cipher` | quantum-safe | 1 | 256 | `2.16.840.1.101.3.4.1` |
| AIMer | `signature` | quantum-safe | 1 | - | - |
| Argon2 | `kdf` | quantum-safe | 0 | - | - |
| ChaCha20 | `stream-cipher` | quantum-safe | 1 | 256 | - |
| Classic McEliece | `kem` | quantum-safe | 5 | - | - |
| FN-DSA (Falcon) | `signature` | quantum-safe | 1 | - | - |
| FrodoKEM | `kem` | quantum-safe | 3 | - | - |
| HAETAE | `signature` | quantum-safe | 2 | - | - |
| HMAC | `mac` | quantum-safe | 1 | 128 | - |
| HQC | `kem` | quantum-safe | 1 | - | - |
| LMS/HSS | `signature` | quantum-safe | 5 | - | - |
| ML-DSA-65 | `signature` | quantum-safe | 3 | - | - |
| ML-DSA-87 | `signature` | quantum-safe | 5 | - | - |
| ML-KEM-1024 | `kem` | quantum-safe | 5 | - | - |
| ML-KEM-512 | `kem` | quantum-safe | 1 | - | - |
| ML-KEM-768 | `kem` | quantum-safe | 3 | - | - |
| NTRU+ | `kem` | quantum-safe | 1 | - | - |
| PBKDF2 | `kdf` | quantum-safe | 0 | - | `1.2.840.113549.1.5.12` |
| SHA-256 | `hash` | quantum-safe | 2 | 128 | `2.16.840.1.101.3.4.2.1` |
| SHA-384 | `hash` | quantum-safe | 4 | 192 | - |
| SHA-512 | `hash` | quantum-safe | 5 | 256 | - |
| SHA3-256 | `hash` | quantum-safe | 2 | 128 | - |
| SLH-DSA | `signature` | quantum-safe | 1 | - | - |
| SMAUG-T | `kem` | quantum-safe | 1 | - | - |
| XMSS/XMSSMT | `signature` | quantum-safe | 5 | - | - |
| bcrypt | `kdf` | quantum-safe | 0 | - | - |
| DSA | `signature` | quantum-vulnerable | 0 | 112 | `1.2.840.10040.4.1` |
| Diffie-Hellman | `key-agree` | quantum-vulnerable | 0 | 112 | - |
| ECDH | `key-agree` | quantum-vulnerable | 0 | 128 | `1.3.132.1.12` |
| ECDSA | `signature` | quantum-vulnerable | 0 | 128 | `1.2.840.10045.4.3` |
| Ed25519 | `signature` | quantum-vulnerable | 0 | 128 | `1.3.101.112` |
| RSA | `pke` | quantum-vulnerable | 0 | 112 | `1.2.840.113549.1.1.1` |
| X25519 | `key-agree` | quantum-vulnerable | 0 | 128 | - |
