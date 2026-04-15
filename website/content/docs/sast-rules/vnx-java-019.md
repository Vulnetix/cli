---
title: "VNX-JAVA-019 – Java hardcoded cryptographic key literal"
description: "Detects cryptographic keys, secrets, and IVs hardcoded as string or byte literals passed to SecretKeySpec, IvParameterSpec, or similar constructors — keys embedded in source code can be extracted from any copy of the binary."
---

## Overview

This rule flags two distinct patterns: `SecretKeySpec` constructed directly from a string literal (e.g., `new SecretKeySpec("mysecretkey12345".getBytes(), "AES")`), and constant declarations where a variable named `SECRET_KEY`, `ENCRYPTION_KEY`, `AES_KEY`, `HMAC_KEY`, `CRYPTO_KEY`, or similar is assigned a string literal. Both patterns indicate that a cryptographic key has been hardcoded into the source code, which is classified as CWE-321 (Use of Hard-coded Cryptographic Key).

A hardcoded key is present in source repositories, compiled `.class` files, JAR archives, Docker images, and any other artifact derived from the source. Anyone with read access to the repository — including contributors, CI workers, third-party auditors, or an attacker who gains access to any artifact — can extract the key and use it to decrypt protected data, forge signatures, or impersonate services. The key cannot be rotated without a code change and a new deployment, making incident response slow and costly.

The severity is critical because a compromised key retroactively compromises all data ever encrypted with it. Unlike a compromised password (which only opens the front door), a compromised encryption key opens every locked cabinet in the house, past and present.

**Severity:** Critical | **CWE:** [CWE-321 – Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)

## Why This Matters

Hardcoded cryptographic keys are a recurring finding in mobile application reverse engineering. Java and Kotlin bytecode can be decompiled with tools like `jadx`, `cfr`, or `procyon` in seconds — the key literal appears exactly as written. For Android apps distributed via the Play Store, any user can download the APK and run it through a decompiler. The Nissan Leaf API exposure (2016) and numerous mobile banking app analyses have demonstrated that this is not a theoretical risk.

In server-side applications, hardcoded keys leak through version control history. Even after a developer removes the key from the codebase and rotates it, the old value remains in `git log` forever. Repositories that are later open-sourced, migrated to a new host, or accidentally made public expose their entire historical key material. GitHub's secret scanning catches many of these cases, but detection after the fact does not undo the exposure.

For HMAC-signed tokens (such as JWTs), a hardcoded signing key means any party who knows the key can forge tokens for any user in the system. For AES encryption, the attacker can decrypt the entire database. The blast radius is proportional to how widely the key was used, which is typically "everywhere the class was instantiated."

## What Gets Flagged

```java
// FLAGGED: key embedded as string literal directly in SecretKeySpec
private static final String KEY_STRING = "SuperSecretKey!!";
SecretKeySpec keySpec = new SecretKeySpec(KEY_STRING.getBytes(), "AES");

// FLAGGED: named constant with hardcoded key value
private static final String SECRET_KEY = "ChangeMe123456789";
private static final String AES_KEY     = "0123456789abcdef";
private static final String HMAC_KEY    = "hmac-signing-key-v1";
```

## Remediation

1. Remove the hardcoded key from source code and delete it from the git history using `git filter-repo` or BFG Repo-Cleaner.
2. Load the key at runtime from an environment variable, a JVM system property, or a dedicated secrets manager such as HashiCorp Vault, AWS Secrets Manager, or GCP Secret Manager.
3. For Java KeyStore-based key management, load the key from a `KeyStore` file whose password is itself provided via environment variable.
4. Rotate any key that was ever hardcoded immediately and re-encrypt all data protected by the old key.

```java
// SAFE: key loaded from environment variable at startup
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class CryptoConfig {
    private final SecretKey aesKey;

    public CryptoConfig() {
        String keyBase64 = System.getenv("APP_AES_KEY");
        if (keyBase64 == null || keyBase64.isBlank()) {
            throw new IllegalStateException(
                "APP_AES_KEY environment variable is not set");
        }
        byte[] keyBytes = Base64.getDecoder().decode(keyBase64);
        if (keyBytes.length != 32) {
            throw new IllegalStateException(
                "APP_AES_KEY must be a 256-bit (32-byte) key encoded in Base64");
        }
        this.aesKey = new SecretKeySpec(keyBytes, "AES");
    }

    public SecretKey getAesKey() {
        return aesKey;
    }
}
```

## References

- [CWE-321: Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)
- [CAPEC-191: Read Sensitive Constants Within an Executable](https://capec.mitre.org/data/definitions/191.html)
- [MITRE ATT&CK T1552: Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [Java SE Security: KeyStore API](https://docs.oracle.com/en/java/javase/17/security/java-cryptography-architecture-jca-reference-guide.html)
- [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning)
