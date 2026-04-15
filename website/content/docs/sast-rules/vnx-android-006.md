---
title: "VNX-ANDROID-006 – Android Hardcoded API Key in strings.xml"
description: "Detects string resources in Android XML value files whose names suggest they hold credentials (api_key, secret, token, password, private_key, auth) and contain non-placeholder values that will be bundled into the APK."
---

## Overview

This rule examines Android resource XML files — specifically `strings.xml` and any XML file under `res/values/` — for `<string>` elements whose `name` attribute matches a credential-related pattern (case-insensitive variants of `api_key`, `secret`, `token`, `password`, `passwd`, `private_key`, `auth`). It additionally requires that the string body contains a non-empty, non-placeholder value (at least four characters that are not `PLACEHOLDER`, `YOUR_`, or `REPLACE`) to minimise noise from documentation examples.

When a credential is placed in `strings.xml`, it is compiled verbatim into the APK's `resources.arsc` file. Anyone who downloads or decompiles the APK — using freely available tools such as `apktool`, `jadx`, or `dex2jar` — can extract every string resource in seconds. This vulnerability maps to CWE-798 (Use of Hard-coded Credentials).

**Severity:** High | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

APK decompilation is trivial. Android applications are distributed as ZIP archives containing DEX bytecode and compiled resources. A credentialed attacker requires no reverse engineering skills beyond running `apktool d app.apk` to recover all string resources, including API keys, cloud service credentials, and third-party SDK tokens. Entire GitHub repositories exist specifically to collect API keys extracted from published APKs.

The consequences depend on what service the credential accesses. A leaked Firebase API key has been used to exfiltrate user databases. A leaked AWS access key embedded in a mobile app has resulted in six-figure cloud billing fraud. A leaked payment processor secret key has enabled fraudulent transactions. In all these cases the application appeared legitimate in the Play Store and millions of users installed it before the credential was discovered and rotated.

The correct approach is never to include long-lived credentials in client-side code. Credentials that must be present at runtime should be fetched from a server-side endpoint after authenticating the user, or injected via the CI/CD pipeline as `BuildConfig` fields from secrets manager-backed environment variables — and even then only for credentials that can be safely scoped to the build artifact.

## What Gets Flagged

```xml
<!-- FLAGGED: API key hardcoded as a string resource (example patterns for testing) -->
<resources>
    <string name="google_api_key">AIzaSyD-9tSrke72I6e0a8oNsHkPbMmv9ABCDEF</string>  <!-- Test pattern, not real key -->
    <string name="stripe_secret_token">sk_live_4eC39HqLyjWDarjtT1zdp7dc</string>  <!-- Test pattern, not real key -->
    <string name="db_password">Sup3rS3cur3!</string>  <!-- Test pattern, not real password -->
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
