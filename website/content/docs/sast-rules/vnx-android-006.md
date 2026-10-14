---
title: "VNX-ANDROID-006 – Android Hardcoded API Key in strings.xml"
description: "Detects a <string> resource in an Android res/values*/ file whose name marks it as a credential (api key, secret, token, password, private or signing key) and whose value is a credential-shaped literal, not UI text, a placeholder, a reference or a public Firebase/Facebook client id."
---

## Overview

This rule examines `<string>` and `<item type="string">` elements in Android values resource files (`res/values*/*.xml`, including `strings.xml`, `secrets.xml`, qualified `values-xx` folders and Compose Multiplatform `composeResources/values`). It reports one whose `name` marks it as a credential (api key, secret, token, password, passphrase, passcode, private, signing, encryption or licence key) and whose value looks like one: at least 8 characters, no whitespace, not a resource or `${build}` reference and not a URL. UI text is not reported (names with hint, label, title, error, message, button and similar, or values that are a sentence, a Title-case word, a snake_case identifier or end in `:`), nor are placeholders (`YOUR_...`, `changeme`, `xxxx`), the Firebase and Facebook client identifiers that are public by design (`google_api_key`, `facebook_client_token`), XML comments, layouts and test source sets. Tokens with a known provider shape are also reported by the generated secret rules.

When a credential is placed in `strings.xml`, it is compiled verbatim into the APK's `resources.arsc` file. Anyone who downloads or decompiles the APK — using freely available tools such as `apktool`, `jadx`, or `dex2jar` — can extract every string resource in seconds. This vulnerability maps to CWE-798 (Use of Hard-coded Credentials).

**Severity:** High | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

APK decompilation is trivial. Android applications are distributed as ZIP archives containing DEX bytecode and compiled resources. A credentialed attacker requires no reverse engineering skills beyond running `apktool d app.apk` to recover all string resources, including API keys, cloud service credentials, and third-party SDK tokens. Entire GitHub repositories exist specifically to collect API keys extracted from published APKs.

The consequences depend on what service the credential accesses. A leaked Firebase API key has been used to exfiltrate user databases. A leaked AWS access key embedded in a mobile app has resulted in six-figure cloud billing fraud. A leaked payment processor secret key has enabled fraudulent transactions. In all these cases the application appeared legitimate in the Play Store and millions of users installed it before the credential was discovered and rotated.

The correct approach is never to include long-lived credentials in client-side code. Credentials that must be present at runtime should be fetched from a server-side endpoint after authenticating the user, or injected via the CI/CD pipeline as `BuildConfig` fields from secrets manager-backed environment variables — and even then only for credentials that can be safely scoped to the build artifact.

## What Gets Flagged

```xml
<resources>
    <!-- FLAGGED: credential-named resources holding credential-shaped values -->
    <string name="payments_api_key">k3J9xQ2mV8pL4tZ7wR1n</string>
    <string name="backend_client_secret">e1f0c9b8a7d6e5f4c3b2</string>
    <string name="db_password">Tr0ub4dor-and-3</string>

    <!-- Not flagged: UI text, placeholders and public client ids -->
    <string name="password_hint">Password</string>
    <string name="api_key">YOUR_API_KEY_HERE</string>
    <string name="google_api_key">AIzaSyPublicClientId</string>
</resources>
```

## Remediation

1. **Remove the credential from `strings.xml` immediately** and rotate it — assume it has already been extracted from any APK that was distributed.

2. **Inject build-time constants via `BuildConfig`** from CI/CD secrets for keys that must be present in the binary. These are harder to discover than string resources but are still extractable, so treat them as low-privilege or scoped keys only.

3. **Fetch credentials at runtime** from a server-side endpoint that authenticates the user first. The mobile client should never hold a long-lived, privileged credential.

4. **Use server-side proxies** for third-party API calls. The mobile app calls your backend, which holds the API key and makes the external request. The key never leaves your infrastructure.

```kotlin
// SAFE: inject a scoped, low-privilege key at build time from CI secret
// In build.gradle:
//   buildConfigField "String", "MAPS_API_KEY", "\"${System.getenv('MAPS_API_KEY')}\""

val mapsKey = BuildConfig.MAPS_API_KEY

// SAFER: fetch a short-lived credential from your own authenticated endpoint
suspend fun getServiceToken(authToken: String): String {
    return apiClient.getToken(bearerToken = authToken)
}
```

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [OWASP MASTG – MASTG-TEST-0013: Testing Memory for Sensitive Data](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0013/)
- [OWASP MASVS – MASVS-STORAGE-2: Prevent Leakage in Logs and Backups](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/)
- [Android Developer Docs – Build configuration fields](https://developer.android.com/build/gradle-tips#share-custom-fields-and-resource-values-with-your-app-code)
- [Google – Protecting API keys in Android apps](https://developers.google.com/maps/api-security-best-practices)
- [MITRE ATT&CK T1552 – Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)
