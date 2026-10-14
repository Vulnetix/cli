---
title: "VNX-ANDROID-003 – Android Exported Component Without Permission Check"
description: "Detects an activity, activity-alias, service, receiver or provider in a production AndroidManifest.xml that is exported (android:exported=\"true\", or an intent-filter with no exported attribute) and requires no permission, excluding components that answer platform actions such as the launcher, deep links and system broadcasts."
---

## Overview

This rule reads each `<activity>`, `<activity-alias>`, `<service>`, `<receiver>` and `<provider>` start tag in a production `AndroidManifest.xml`, wherever its attributes are split across lines, and reports it when it is exported and requires no permission. Exported means `android:exported="true"`, or (for activities, services and receivers) an `<intent-filter>` with no `android:exported` attribute, which exports the component on API 30 and lower. Protected means `android:permission`, or for a provider both `android:readPermission` and `android:writePermission`. Components whose intent filters answer a platform action (`android.*` or `com.google.android.*`: the launcher entry, deep links, share targets, system broadcasts) are public by design and not reported, nor are components with `tools:node="remove"` or `android:enabled="false"`, manifests in debug and test source sets or sample modules, and XML comments. Whether the permission's protection level is strong enough is not judged.

Without a required permission, any application installed on the same device can send an Intent directly to the exported component. There is no OS-level enforcement preventing a malicious or misconfigured app from invoking that Activity, binding to that Service, subscribing to that BroadcastReceiver, or querying that ContentProvider. This vulnerability maps to CWE-926 (Improper Export of Android Application Components).

On API level 31 and above, Android requires an explicit `android:exported` attribute on any component that has an intent filter, so the number of unintentionally exported components is growing as developers add the attribute to satisfy the build requirement without adding the corresponding permission.

**Severity:** High | **CWE:** [CWE-926 – Improper Export of Android Application Components](https://cwe.mitre.org/data/definitions/926.html)

## Why This Matters

An exported component with no permission check is effectively a public API on the device. Any other app — including a malicious one side-loaded or installed from a third-party store — can invoke it. Depending on the component type the impact varies: an exported Activity may expose a sensitive screen or deep link flow without authentication; an exported Service may allow binding and triggering privileged background operations; an exported BroadcastReceiver may allow injecting fake system events; an exported ContentProvider may allow reading or writing arbitrary data rows.

A real-world example is the CVE-2013-4787 (Master Key) class of Android vulnerabilities, where exported components were used to bypass signature verification. More recently, banking trojans on Android routinely enumerate exported services in victim apps to trigger fund transfer screens. OWASP Mobile Security Testing Guide test MASTG-TEST-0025 specifically requires verifying that all exported components require a permission or limit their attack surface via intent filter validation.

The CAPEC-1 attack pattern ("Accessing/Intercepting/Modifying HTTP Cookies") and the broader class of privilege escalation attacks on Android (ATT&CK T1427) rely on the ability to invoke exported components that were not intended for third-party use.

## What Gets Flagged

```xml
<!-- FLAGGED: exported, no permission -->
<activity
    android:name=".admin.AdminConsoleActivity"
    android:exported="true" />

<!-- FLAGGED: a custom-action intent filter with no android:exported (exported on API 30 and lower) -->
<receiver android:name=".sync.SyncTrigger">
    <intent-filter>
        <action android:name="com.example.bank.ACTION_SYNC" />
    </intent-filter>
</receiver>

<!-- FLAGGED: a provider with only a read permission -->
<provider
    android:name=".data.AccountsProvider"
    android:authorities="com.example.bank.accounts"
    android:exported="true"
    android:readPermission="com.example.bank.READ_ACCOUNTS" />
```

Not flagged: the `android.intent.action.MAIN` launcher activity, a `VIEW`/`BROWSABLE` deep-link activity, or a service with `android:permission="com.example.bank.permission.BIND_SYNC"`.

## Remediation

1. **Add `android:permission` to every exported component** with a signature-level or custom permission. Signature-level permissions (`android:protectionLevel="signature"`) ensure only apps signed with the same certificate can invoke the component.

2. **Remove `android:exported="true"` entirely** for any component that does not need to be invoked by other apps. An unexported component is invisible to other applications.

3. **Use intent filter validation** in the component's `onStartCommand`, `onBind`, or `onCreate` methods to verify the caller's intent even when the component must remain exported.

```xml
<!-- SAFE: custom signature-level permission protecting the component -->
<permission
    android:name="com.example.CALL_ADMIN"
    android:protectionLevel="signature" />

<activity
    android:name=".AdminActivity"
    android:exported="true"
    android:permission="com.example.CALL_ADMIN" />
```

```xml
<!-- SAFE: component not needed by third parties, so not exported -->
<service
    android:name=".SyncService"
    android:exported="false" />
```

## References

- [CWE-926: Improper Export of Android Application Components](https://cwe.mitre.org/data/definitions/926.html)
- [Android Developer Docs – android:exported](https://developer.android.com/guide/topics/manifest/activity-element#exported)
- [Android Developer Docs – android:permission](https://developer.android.com/guide/topics/manifest/activity-element#prmsn)
- [OWASP MASTG – MASTG-TEST-0025: Testing for Exported Activities](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0025/)
- [OWASP Mobile Application Security Verification Standard – MASVS-PLATFORM-1](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-1/)
- [MITRE ATT&CK T1427 – Attack PC via USB](https://attack.mitre.org/techniques/T1427/)
