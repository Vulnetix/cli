---
title: "VNX-SWIFT-001 – Swift Hardcoded API Key or Secret in Source"
description: "Detects passwords, API keys, client secrets, tokens and private keys given as string literals in Swift declarations, assignments, argument labels, dictionaries and HTTP header values, password comparisons with a literal, and Bearer/Basic Authorization literals; placeholders, lookup keys, identifier and path constants, interpolated strings and test files are not reported."
---

## Overview

This rule reports a Swift string literal that holds a credential: a `let`/`var` declaration (with or without a type annotation and modifiers), a property assignment, a call argument label (`apiKey: "…"`, `password: "…"`) or a dictionary key whose name ends with password, passwd, pwd, passphrase, secret, apiKey, token, privateKey, credential(s) or an encryption/signing/HMAC/master key, and a `"Bearer …"`/`"Basic …"`/`"Token …"` header literal with a credential of 16 or more characters. The value must be at least six characters.

It does not report placeholders (`YOUR_API_KEY_HERE`, `<client-secret>`, `****`, `$(CLIENT_SECRET)`), interpolated or empty strings, lookup keys rather than values (`"access_token"`, `"user_password"`, `"com.example.app.token"`, `"API_KEY"`, `"X-Client-Secret"`), prose with spaces, URLs, names that only describe a credential (`passwordKey`, `passwordHint`, `tokenStorageKey`), `CodingKeys` cases, values read at runtime, comments and test files.

Hardcoding secrets directly in source code creates a credential that is permanently tied to the codebase. Anyone who gains access to the repository, the compiled `.ipa` archive, or a decompiled version of the binary can extract the value verbatim. Unlike a rotated environment variable or a Keychain-backed credential, a hardcoded secret cannot be invalidated without shipping a new binary and removing the old one from circulation.

This maps to [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html).

**Severity:** High | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Automated secret scanning tools are routinely run against public GitHub repositories, npm packages, and leaked CI artefacts. Services such as GitHub Secret Scanning, truffleHog, and GitGuardian continuously index public commits and will alert the issuing service the moment a recognised credential pattern appears. Even if the repository is private today, a future repository visibility change, a misconfigured fork, or a compromised CI log can expose it.

Mobile binaries present an additional attack vector. iOS `.ipa` files are ZIP archives; anyone who obtains a copy — through TestFlight, enterprise distribution, a jailbroken device, or a backup — can unzip the archive and use `strings` or a Mach-O disassembler to extract all string literals in seconds. API keys embedded in the binary are therefore available to every device that runs the app, not just the developers who wrote the code.

Rotating a hardcoded credential requires a code change, a review cycle, a new build, and re-distribution to all users. For any credential that controls billing, data access, or third-party integrations, this rotation window leaves the service exposed. Storing credentials externally and fetching them at runtime means rotation can happen without touching the binary at all.

**Severity:** High | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## What Gets Flagged

```swift
// FLAGGED: API key assigned directly as a string literal
private let apiKey = "k3Jd9sLq02MZpXa7Vt4c"

// FLAGGED: client secret with a type annotation
static let clientSecret: String = "c9f1e2a7b3d84c6f9e0a1b2c3d4e5f60"

// FLAGGED: SDK key passed as an argument label
Analytics.startSession(apiKey: "Q7RM2HP62885AQXFKZDX", options: .default)

// FLAGGED: password in a request dictionary
let body: [String: Any] = ["username": "sync-bot", "password": "Pa55w0rd!2023"]

// FLAGGED: a header-style key and a password compared with a literal
request.setValue("Qm9vdHN0cmFwS2V5MjAyNA77", forHTTPHeaderField: "X-Api-Key")
if passwordTextField.text == "Sup3r#Adm1n" { showHome() }

// NOT FLAGGED: lookup keys, identifiers, paths and placeholders
static let passwordKey = "user_password"
static let showPassword = "showPasswordSegue"
static let token = "/oauth2/token"
let apiKey = "YOUR_API_KEY_HERE"
```

## Remediation

1. **Remove every hardcoded credential from Swift source.** Delete the string literal and replace it with a call to a secure retrieval mechanism.

2. **Store user credentials and session tokens in the iOS Keychain.** The `Security` framework's `SecItemAdd`, `SecItemCopyMatching`, and `SecItemUpdate` APIs encrypt values using the device's Secure Enclave-backed key material.

   ```swift
   // SAFE: store and retrieve a token using the Keychain
   import Security

   func saveToken(_ token: String, forKey key: String) throws {
       let data = Data(token.utf8)
       let query: [CFString: Any] = [
           kSecClass: kSecClassGenericPassword,
           kSecAttrAccount: key,
           kSecValueData: data,
           kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
       ]
       SecItemDelete(query as CFDictionary)
       let status = SecItemAdd(query as CFDictionary, nil)
       guard status == errSecSuccess else { throw KeychainError.saveFailed(status) }
   }

   func loadToken(forKey key: String) throws -> String {
       let query: [CFString: Any] = [
           kSecClass: kSecClassGenericPassword,
           kSecAttrAccount: key,
           kSecReturnData: true,
           kSecMatchLimit: kSecMatchLimitOne,
       ]
       var result: AnyObject?
       let status = SecItemCopyMatching(query as CFDictionary, &result)
       guard status == errSecSuccess, let data = result as? Data,
             let token = String(data: data, encoding: .utf8) else {
           throw KeychainError.loadFailed(status)
       }
       return token
   }
   ```

3. **Fetch server-side secrets at runtime.** API keys that grant access to backend services should live on a server you control and be returned only to authenticated, authorised clients. The app presents its own identity (e.g., a device attestation token), not a raw API key.

4. **Use environment variables or a secrets file excluded from version control during development.** For build-time constants, inject them via Xcode build settings (`$(MY_API_KEY)`) sourced from a local `.xcconfig` file listed in `.gitignore`.

5. **Audit your git history.** Removing the secret from HEAD does not remove it from history. Use `git filter-repo` or the GitHub secret scanning remediation flow to purge the value, then rotate the credential immediately.

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [OWASP Mobile Security Testing Guide – MSTG-STORAGE-14 (Sensitive Data in Source Code)](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0061/)
- [Apple – Keychain Services API](https://developer.apple.com/documentation/security/keychain_services)
- [Apple – Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- [MITRE ATT&CK T1552 – Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)
- [CAPEC-191: Read Sensitive Constants Within an Executable](https://capec.mitre.org/data/definitions/191.html)
- [GitHub – Secret Scanning](https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning)
