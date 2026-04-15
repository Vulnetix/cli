---
title: "VNX-ANDROID-001 – Android Insecure Manifest Configuration"
description: "Detects insecure AndroidManifest.xml settings such as android:debuggable='true' and android:allowBackup='true' that expose apps to debugging attacks and data extraction."
---

## Overview

This rule detects dangerous configuration flags in `AndroidManifest.xml` that are commonly enabled during development but must be disabled before shipping to production. Flags such as `android:debuggable="true"`, `android:allowBackup="true"`, `android:usesCleartextTraffic="true"`, and `android:exported="true"` each widen the attack surface of the application in distinct ways. Taken together, they represent a class of misconfiguration vulnerabilities covered by CWE-489 (Active Debug Code) and CWE-921 (Storage of Sensitive Data in a Mechanism without Access Control).

**Severity:** High | **CWE:** [CWE-489 – Active Debug Code](https://cwe.mitre.org/data/definitions/489.html), [CWE-921 – Storage of Sensitive Data in a Mechanism without Access Control](https://cwe.mitre.org/data/definitions/921.html)

## Why This Matters

When `android:debuggable="true"` is present in a production APK, any user with `adb` access — or any app running with `android.permission.GET_TASKS` — can attach a debugger to the process, inspect heap memory, override method return values, and exfiltrate secrets. The 2012 Skype Android data-leakage incident and several banking-trojan campaigns have exploited debuggable flags left in production releases.

`android:allowBackup="true"` lets any computer with `adb` execute `adb backup` against the app without root, pulling the entire private data directory — databases, tokens, session cookies — onto the attacker's machine. `android:usesCleartextTraffic="true"` permits HTTP connections, exposing data in transit to network-level interception. `android:exported="true"` on Activities, Services, or BroadcastReceivers allows other apps to invoke them without permission checks, enabling privilege escalation and data theft.

## What Gets Flagged

The rule scans every file in the project for the four indicator strings. Any line containing one of these strings in any file will produce a finding, making it effective for detecting manifest flags that may be templated, generated, or duplicated across modules.

```xml
<!-- FLAGGED: debuggable flag left on for production -->
<application
    android:debuggable="true"
    android:allowBackup="true"
    android:usesCleartextTraffic="true"
    ... >
```

```xml
<!-- FLAGGED: component exported without explicit permission -->
<activity
    android:name=".DeepLinkActivity"
    android:exported="true" />
```

## Remediation

1. **Disable debuggable in all release build types.** In `build.gradle` (or `build.gradle.kts`) ensure the release build type explicitly sets `debuggable false`. Never rely on the default, as some CI configurations override it.

   ```groovy
   // SAFE: release build type with explicit security flags
   buildTypes {
       release {
           debuggable false
           minifyEnabled true
           proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
       }
   }
   ```

2. **Disable backup or define a backup rules file.** Set `android:allowBackup="false"` unless cloud backup is a deliberate product feature. If you need selective backup, use `android:fullBackupContent` with an XML rules file that excludes sensitive files.

   ```xml
   <!-- SAFE: backup disabled for sensitive apps -->
   <application
       android:allowBackup="false"
       android:debuggable="false"
       ... >
   ```

3. **Remove `android:usesCleartextTraffic="true"`.** Define a Network Security Configuration file instead, and whitelist only the specific domains that require cleartext (none, ideally).

4. **Lock down exported components.** Only set `android:exported="true"` on components that genuinely need to be invoked by other apps. Add `android:permission` to require a declared permission, and use intent filters carefully — any component with an intent filter defaults to exported on API level < 31.

5. **Automate enforcement.** Add a lint rule or a build script assertion that fails the build if the release APK manifest contains `debuggable=true` or `allowBackup=true`. The Android Gradle plugin will also emit warnings for these flags.

## References

- [CWE-489: Active Debug Code](https://cwe.mitre.org/data/definitions/489.html)
- [CWE-921: Storage of Sensitive Data in a Mechanism without Access Control](https://cwe.mitre.org/data/definitions/921.html)
- [CAPEC-37: Retrieve Embedded Sensitive Data](https://capec.mitre.org/data/definitions/37.html)
- [MITRE ATT&CK T1409 – Stored Application Data](https://attack.mitre.org/techniques/T1409/)
- [Android Security: android:debuggable](https://developer.android.com/guide/topics/manifest/application-element#debug)
- [Android Backup Documentation](https://developer.android.com/guide/topics/data/backup)
- [Android Network Security Configuration](https://developer.android.com/training/articles/security-config)
- [OWASP Mobile Security Testing Guide – MSTG-STORAGE-7](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0012/)
