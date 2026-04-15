---
title: "VNX-ANDROID-005 – Android Network Security Config Allows Plaintext HTTP Traffic"
description: "Detects cleartextTrafficPermitted='true' in Android network security configuration XML files, which permits unencrypted HTTP connections that can be intercepted by network attackers."
---

## Overview

This rule scans XML files for the attribute `cleartextTrafficPermitted="true"` within Android network security configuration files. Android's Network Security Configuration (NSC) framework, introduced in API level 24, allows developers to declaratively control network security behaviour including which domains may use plaintext HTTP traffic. Setting `cleartextTrafficPermitted="true"` globally or for specific domains overrides the platform default, which since Android 9 (API 28) blocks cleartext traffic for all apps by default.

When cleartext traffic is permitted, the app sends HTTP requests without TLS encryption. Any passive observer on the same Wi-Fi network, a rogue access point, or an active man-in-the-middle attacker can intercept, read, and modify all HTTP communication between the device and any server the app contacts over cleartext. This vulnerability maps to CWE-319 (Cleartext Transmission of Sensitive Information).

**Severity:** High | **CWE:** [CWE-319 – Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

## Why This Matters

Public Wi-Fi interception is a well-documented real-world attack. Tools like `mitmproxy`, `Bettercap`, and `SSLstrip` allow attackers on shared networks to transparently intercept and modify HTTP traffic. Users who connect to a hotel, airport, or café Wi-Fi are routinely targeted. When a banking or healthcare app permits cleartext traffic, authentication tokens, session cookies, and personal data flow in the clear over the network layer.

Android's decision to default-block cleartext traffic from API 28 onwards was a direct response to the prevalence of HTTP interception on mobile. Re-enabling it via the NSC explicitly undoes that protection. OWASP MASTG test MASTG-TEST-0012 treats `cleartextTrafficPermitted="true"` as a critical finding, and Google Play policies warn against apps that transmit PII over cleartext connections.

The ATT&CK technique T1557 (Man-in-the-Middle) covers exactly this class of attack: an adversary positioned between the app and the server manipulates traffic, which is trivially achievable when TLS is not used.

## What Gets Flagged

```xml
<!-- FLAGGED: global cleartext permitted in network security config -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>
```

```xml
<!-- FLAGGED: cleartext permitted for a specific domain -->
<network-security-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">api.example.com</domain>
    </domain-config>
</network-security-config>
```

## Remediation

1. **Set `cleartextTrafficPermitted="false"` globally** in your network security configuration. This is the default on API 28+, but making it explicit documents intent and prevents accidental regression.

2. **Migrate all API endpoints to HTTPS.** No legitimate production endpoint should require HTTP. If a third-party SDK or backend service only supports HTTP, escalate to that vendor — do not lower app security to accommodate it.

3. **Remove any NSC overrides that re-enable cleartext** that were added for debugging. Use proxy-aware debug configurations scoped to debug build types only.

```xml
<!-- SAFE: all cleartext explicitly disabled -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>
```

```xml
<!-- SAFE: debug overrides scoped to debug builds only via res/xml/network_security_config_debug.xml -->
<network-security-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
    <base-config cleartextTrafficPermitted="false" />
</network-security-config>
```

## References

- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [Android Developer Docs – Network Security Configuration](https://developer.android.com/training/articles/security-config)
- [OWASP MASTG – MASTG-TEST-0012: Testing for Unencrypted Sensitive Data on the Network](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0012/)
- [OWASP MASVS – MASVS-NETWORK-1: Secure Network Communication](https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/)
- [CAPEC-94: Adversary in the Middle (CAPEC)](https://capec.mitre.org/data/definitions/94.html)
- [MITRE ATT&CK T1557 – Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)
