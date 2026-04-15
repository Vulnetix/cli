---
title: "VNX-ANDROID-004 – Android SharedPreferences Used for Sensitive Data Storage"
description: "Detects calls to SharedPreferences.putString() that store password, token, secret, or key values in the plaintext SharedPreferences XML store, exposing credentials to root access, backups, and memory forensics."
---

## Overview

This rule identifies Java and Kotlin code that calls `putString()` within a `SharedPreferences` editing context where the key or value being stored carries a name suggesting it holds sensitive data: passwords, tokens, secrets, API keys, private keys, auth tokens, access tokens, or session identifiers. The rule inspects a 15-line window around each `putString()` call to confirm that a `SharedPreferences` object is in scope.

`SharedPreferences` stores data as a plaintext XML file under the app's private data directory (e.g., `/data/data/com.example.app/shared_prefs/`). While `MODE_PRIVATE` prevents other apps from reading the file directly, the data remains fully visible on rooted devices, is included in unencrypted `adb backup` archives, and can be recovered through memory forensics or device backup services. This vulnerability maps to CWE-312 (Cleartext Storage of Sensitive Information).

**Severity:** High | **CWE:** [CWE-312 – Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)

## Why This Matters

Many high-profile Android breaches have involved credential theft from plaintext local storage. Attackers who obtain a device backup — via a compromised computer running `adb`, a malicious backup app, or a cloud backup service — can trivially extract `SharedPreferences` XML files and read every stored value. On rooted devices, any app can open another app's `SharedPreferences` files directly. Memory forensics tools such as LiME can dump app heap and reconstruct the `SharedPreferences` map without ever touching the filesystem.

The Android Keystore system exists precisely to address this risk. Credentials encrypted and stored through Keystore are bound to the device hardware and cannot be extracted in usable form even from a rooted device. The Jetpack Security library's `EncryptedSharedPreferences` class provides a drop-in replacement for `SharedPreferences` that transparently encrypts both keys and values using AES-256-GCM and an Keystore-backed master key.

OWASP MASTG test MASTG-TEST-0001 (Testing Local Data Storage for Sensitive Data) specifically checks for credentials in `SharedPreferences` and considers it a critical finding.

## What Gets Flagged

```java
// FLAGGED: storing a token directly in SharedPreferences
SharedPreferences prefs = getSharedPreferences("auth", MODE_PRIVATE);
SharedPreferences.Editor editor = prefs.edit();
editor.putString("authToken", token);
editor.apply();
```

```kotlin
// FLAGGED: storing a password in SharedPreferences
val prefs = getSharedPreferences("user", Context.MODE_PRIVATE)
prefs.edit().putString("password", userPassword).apply()
```

## Remediation

1. **Use `EncryptedSharedPreferences` from Jetpack Security** for all sensitive values. This is a direct API-compatible replacement that encrypts both keys and values.

2. **Use the Android Keystore system** for long-lived secrets and cryptographic key material. Keys generated in Keystore cannot be exported from the device.

3. **Avoid storing credentials locally at all** where possible. Store only short-lived session tokens and refresh them frequently.

```java
// SAFE: encrypted storage via Jetpack Security EncryptedSharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;

MasterKey masterKey = new MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build();

SharedPreferences encryptedPrefs = EncryptedSharedPreferences.create(
    context,
    "secure_prefs",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
);

encryptedPrefs.edit().putString("authToken", token).apply();
```

## References

- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- [Android Developer Docs – EncryptedSharedPreferences](https://developer.android.com/reference/androidx/security/crypto/EncryptedSharedPreferences)
- [Android Developer Docs – Android Keystore System](https://developer.android.com/training/articles/keystore)
- [OWASP MASTG – MASTG-TEST-0001: Testing Local Data Storage](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0001/)
- [OWASP MASVS – MASVS-STORAGE-1: Sensitive Data Storage](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/)
- [MITRE ATT&CK T1409 – Stored Application Data](https://attack.mitre.org/techniques/T1409/)
