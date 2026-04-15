---
title: "VNX-SWIFT-003 – Swift Insecure Data Storage via UserDefaults for Sensitive Values"
description: "Detects sensitive data such as passwords, tokens, and keys being written to UserDefaults, which stores data as an unencrypted plist file accessible via device backup and privileged processes."
---

## Overview

This rule identifies Swift lines that call `UserDefaults.set(` while also referencing a sensitive term in the same statement: `password`, `passwd`, `token`, `secret`, `apiKey`, `apikey`, `api_key`, `privateKey`, `private_key`, `authToken`, or `auth_token`. The combination of a `UserDefaults` write and a credential-like identifier on a single line indicates that sensitive data is being persisted in an insecure location.

`UserDefaults` (formerly `NSUserDefaults`) serialises data to a plaintext property list file stored at `Library/Preferences/<bundle-id>.plist` in the application sandbox. This file is not encrypted at the application layer. While iOS encrypts the file system at rest using hardware-backed data protection, the plist is stored under the default protection class `NSFileProtectionCompleteUntilFirstUserAuthentication`, which means it is accessible whenever the device has been unlocked at least once after boot — including while the screen is locked.

This maps to [CWE-311: Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html).

**Severity:** High | **CWE:** [CWE-311 – Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)

## Why This Matters

The `UserDefaults` plist is included in iTunes and iCloud device backups by default. An attacker with access to a backup — obtained from an insecure backup destination, a compromised macOS machine, or a social engineering attack against Apple support — can extract the plist and read all stored values in plain text using any standard property list editor.

On jailbroken devices, any process running as `mobile` can read another application's preferences plist without special permissions. Malware on a jailbroken device routinely harvests `UserDefaults` from banking, email, and social applications to collect session tokens. Additionally, MDM profiles can read application preferences on enrolled devices, creating a risk of credential exposure in enterprise deployments.

iOS provides the Keychain specifically to address these threats. The Keychain encrypts each item with a key derived from the device passcode and the item's accessibility class. Items marked `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` can only be read when the device is unlocked and cannot be restored to a different device, providing strong protection against backup extraction and device transfer attacks.

## What Gets Flagged

```swift
// FLAGGED: authentication token written to UserDefaults
UserDefaults.standard.set(authToken, forKey: "auth_token")

// FLAGGED: password persisted in preferences
UserDefaults.standard.set(password, forKey: "userPassword")

// FLAGGED: API key stored unencrypted
defaults.set(apiKey, forKey: "api_key")

// FLAGGED: private key material in UserDefaults
UserDefaults.standard.set(privateKey, forKey: "privateKey")
```

## Remediation

1. **Replace all `UserDefaults` writes of sensitive data with Keychain writes.** The iOS Security framework's Keychain services API provides hardware-backed encryption at no additional complexity cost.

   ```swift
   // SAFE: store a credential in the Keychain
   import Security

   enum KeychainError: Error {
       case saveFailed(OSStatus)
       case loadFailed(OSStatus)
       case itemNotFound
   }

   func saveToKeychain(value: String, key: String) throws {
       guard let data = value.data(using: .utf8) else { return }
       let query: [CFString: Any] = [
           kSecClass: kSecClassGenericPassword,
           kSecAttrService: Bundle.main.bundleIdentifier ?? "app",
           kSecAttrAccount: key,
           kSecValueData: data,
           kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
       ]
       // Delete any existing item before adding
       SecItemDelete(query as CFDictionary)
       let status = SecItemAdd(query as CFDictionary, nil)
       guard status == errSecSuccess else {
           throw KeychainError.saveFailed(status)
       }
   }
   ```

2. **Use a Keychain wrapper library to reduce boilerplate.** Libraries such as KeychainAccess or SwiftKeychainWrapper provide a `UserDefaults`-like interface backed by the Keychain, making migration straightforward.

   ```swift
   // SAFE: Keychain wrapper with familiar interface
   import KeychainAccess

   let keychain = Keychain(service: "com.example.MyApp")
   try keychain.set(authToken, key: "auth_token")
   let token = try keychain.getString("auth_token")
   ```

3. **Audit all `UserDefaults` usage.** Search for `.set(` calls on `UserDefaults` instances and review every key being written. Non-sensitive preferences (theme, locale, feature flags) can remain in `UserDefaults`; credentials, tokens, and keys must move to the Keychain.

4. **Apply the correct accessibility class.** Use `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` for most credentials. Avoid `kSecAttrAccessibleAlways` or any class without `ThisDeviceOnly` unless you explicitly need iCloud Keychain synchronisation and have assessed the implications.

5. **Migrate existing users' data.** On first launch after the update, read any credentials previously stored in `UserDefaults`, move them to the Keychain, and then delete the `UserDefaults` entries.

## References

- [CWE-311: Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)
- [OWASP Mobile Security Testing Guide – MSTG-STORAGE-1 (Local Storage)](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0053/)
- [Apple – Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
- [Apple – Protecting user data with improved data protections](https://developer.apple.com/news/releases/)
- [Apple – SecItemAdd](https://developer.apple.com/documentation/security/1401659-secitemadd)
- [CAPEC-37: Retrieve Embedded Sensitive Data](https://capec.mitre.org/data/definitions/37.html)
- [MITRE ATT&CK T1409 – Stored Application Data](https://attack.mitre.org/techniques/T1409/)
