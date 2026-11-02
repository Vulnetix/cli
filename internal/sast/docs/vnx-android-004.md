---
title: "VNX-ANDROID-004 – Android SharedPreferences Used for Sensitive Data Storage"
description: "Detects a password, token, secret, API or private key, PIN or session id written with putString() to a plain (not Encrypted) SharedPreferences editor in Java or Kotlin, where the key or value names the credential and the value is not encrypted or hashed first."
---

## Overview

This rule reports Java and Kotlin `putString()` calls on a recognisable `SharedPreferences.Editor` (`prefs.edit().putString(...)`, also chained over lines; an editor variable assigned from `.edit()` or declared `SharedPreferences.Editor`; a receiver-less `putString` inside a Kotlin `edit { }` block) when the key or value expression names a credential: password, token, secret, API or private key, PIN, session id. It does not report `EncryptedSharedPreferences`, values passed through an encrypt, cipher, hash or HMAC call (on the line or assigned a few lines above), constant values used to clear or label, keys that only describe a credential (`token_type`, `password_hint`, `remember_password`), push and FCM registration tokens, `Bundle` and `Intent` extras, comments and strings.

`SharedPreferences` stores data as a plaintext XML file under the app's private data directory (e.g., `/data/data/com.example.app/shared_prefs/`). While `MODE_PRIVATE` prevents other apps from reading the file directly, the data remains fully visible on rooted devices, is included in unencrypted `adb backup` archives, and can be recovered through memory forensics or device backup services. This vulnerability maps to CWE-312 (Cleartext Storage of Sensitive Information).

**Severity:** High | **CWE:** [CWE-312 – Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)

## Why This Matters

Many high-profile Android breaches have involved credential theft from plaintext local storage. Attackers who obtain a device backup — via a compromised computer running `adb`, a malicious backup app, or a cloud backup service — can trivially extract `SharedPreferences` XML files and read every stored value. On rooted devices, any app can open another app's `SharedPreferences` files directly. Memory forensics tools such as LiME can dump app heap and reconstruct the `SharedPreferences` map without ever touching the filesystem.

The Android Keystore system exists precisely to address this risk. Credentials encrypted and stored through Keystore are bound to the device hardware and cannot be extracted in usable form even from a rooted device. The Jetpack Security library's `EncryptedSharedPreferences` class provides a drop-in replacement for `SharedPreferences` that transparently encrypts both keys and values using AES-256-GCM and an Keystore-backed master key.

OWASP MASTG test MASTG-TEST-0001 (Testing Local Data Storage for Sensitive Data) specifically checks for credentials in `SharedPreferences` and considers it a critical finding.

## What Gets Flagged

```java
// FLAGGED: an auth token through an editor variable
SharedPreferences.Editor editor = prefs.edit();
editor.putString("auth_token", token);

// FLAGGED: a password through the default preferences chain
PreferenceManager.getDefaultSharedPreferences(this).edit()
        .putString(KEY_PASSWORD, password)
        .apply();
```

```kotlin
// FLAGGED: inside the KTX edit { } block
prefs.edit {
    putString("refresh_token", tokens.refreshToken)
}
```

Not flagged: the same call on preferences created by `EncryptedSharedPreferences.create(...)`, `putString("password_hint", hint)`, `putString("auth_token", null)`, or `putString("pin", hash(pin))`.

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
