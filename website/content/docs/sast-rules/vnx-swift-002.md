---
title: "VNX-SWIFT-002 – Swift NSLog with Potentially Sensitive Data"
description: "Detects NSLog calls that include sensitive terms such as passwords, tokens, and PII, which write data to the system console log readable by any application on the device."
---

## Overview

This rule scans Swift source files for lines that both call `NSLog(` and contain at least one sensitive term: `password`, `passwd`, `token`, `secret`, `apiKey`, `api_key`, `privateKey`, `private_key`, `credential`, `ssn`, `creditCard`, or `credit_card`. When both conditions are true on the same line, a finding is produced.

`NSLog` writes output to the Apple System Log (ASL) facility and to the Xcode console. On iOS, this data is accessible to any application running on the same device through the `asl_search` API and, on older versions of iOS, was additionally readable via iTunes file sharing and device backups. Even on current iOS versions, log output persists on the device and can be retrieved by anyone with physical access or an MDM profile.

This maps to [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html).

**Severity:** Medium | **CWE:** [CWE-532 – Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)

## Why This Matters

Diagnostic logging is one of the most common routes through which credentials and personal data leave a controlled environment. Development teams add logging for debugging and rarely audit it before release. Once a password or token appears in the system log, it is no longer under the application's control: it persists in the log store, is included in crash reports that may be sent to Apple or third-party crash analytics SDKs, and can be read by any code running on the device.

On devices enrolled in Mobile Device Management, administrators (and compromised MDM infrastructure) can collect system logs remotely. Enterprise applications are frequently deployed on corporate-managed devices, making log-based data leakage a realistic threat in B2B contexts. Penetration testers regularly extract system logs from jailbroken test devices as part of mobile application security assessments.

Switching from `NSLog` to the modern `os_log` API with the `.private` privacy annotation ensures that sensitive values are redacted in the system log in non-development builds, limiting exposure to the developer's own machine during active debugging sessions.

## What Gets Flagged

```swift
// FLAGGED: password value logged via NSLog
NSLog("User login: %@, password: %@", username, password)

// FLAGGED: token included in a debug log
NSLog("Auth response token: \(authToken)")

// FLAGGED: API key in an error log statement
NSLog("Request failed — apiKey=%@", apiKey)

// FLAGGED: credential data logged for diagnostics
NSLog("Keychain credential retrieved: %@", credential)
```

## Remediation

1. **Remove sensitive values from all log statements.** Log the fact that an operation occurred, not the data involved. Replace `NSLog("Token: \(token)")` with `NSLog("Token loaded successfully")`.

2. **Migrate from `NSLog` to `os_log` with privacy annotations.** The `os_log` API allows you to mark individual interpolated values as `.private` so they are redacted in production log output and only visible in development builds attached to Xcode.

   ```swift
   // SAFE: sensitive value marked .private — redacted in production logs
   import os.log

   let logger = Logger(subsystem: "com.example.MyApp", category: "auth")

   func handleLogin(username: String, token: String) {
       // username is public, token is private (redacted outside Xcode)
       logger.info("Login succeeded for \(username, privacy: .public) — token loaded")
       logger.debug("Token value: \(token, privacy: .private)")
   }
   ```

3. **Audit existing log statements.** Search the codebase for `NSLog`, `print(`, and `debugPrint(` calls and review each one for sensitive content. Remove or redact any that touch authentication data, PII, or financial information.

4. **Use a build flag to disable verbose logging in release builds.** Wrap debug-only logging in `#if DEBUG` compiler directives so it is compiled out of production binaries entirely.

   ```swift
   // SAFE: debug logging only compiled in DEBUG builds
   #if DEBUG
   logger.debug("Auth token loaded (debug only): \(token, privacy: .private)")
   #endif
   ```

5. **Configure your crash reporting SDK to scrub logs.** If you use a third-party crash reporter, verify that it does not collect system log output, or configure it to exclude log categories that may contain sensitive data.

## References

- [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)
- [OWASP Mobile Security Testing Guide – MSTG-STORAGE-3 (Sensitive Data in Logs)](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0051/)
- [Apple – Logging (os_log)](https://developer.apple.com/documentation/os/logging)
- [Apple – Privacy Annotations in os_log](https://developer.apple.com/documentation/os/oslogprivacy)
- [CAPEC-215: Fuzzing for application mapping](https://capec.mitre.org/data/definitions/215.html)
- [MITRE ATT&CK T1552 – Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)
- [Apple Human Interface Guidelines – Privacy](https://developer.apple.com/design/human-interface-guidelines/privacy)
