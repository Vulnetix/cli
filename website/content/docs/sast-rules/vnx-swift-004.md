---
title: "VNX-SWIFT-004 – Swift TLS Certificate Validation Disabled in URLSession or Alamofire"
description: "Detects patterns that bypass TLS certificate validation in URLSession delegate callbacks and Alamofire trust policies, making the app vulnerable to man-in-the-middle attacks."
---

## Overview

This rule detects three distinct code patterns in Swift files that each indicate TLS certificate validation has been bypassed:

1. Use of `URLCredential(trust:)` — constructing a credential that unconditionally trusts the server's certificate chain.
2. Calling `completionHandler(.useCredential, ...)` inside a `didReceive challenge` delegate method without inspecting `serverTrust` — accepting a credential in an authentication challenge without performing certificate evaluation.
3. Setting `disableEvaluation`, `DisableTrustEvaluation`, or `.disabled` within a block that references `ServerTrustPolicy`, `ServerTrustEvaluating`, or `TrustEvaluation` — disabling Alamofire's server trust evaluation.

All three patterns result in the application accepting any certificate presented by the server, including self-signed, expired, and attacker-controlled certificates.

This maps to [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html).

**Severity:** High | **CWE:** [CWE-295 – Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

## Why This Matters

Disabling TLS certificate validation eliminates the only mechanism that proves the server the application is communicating with is who it claims to be. On any untrusted network — public Wi-Fi, hotel networks, carrier networks with traffic inspection appliances — an attacker can perform a man-in-the-middle (MITM) attack by presenting their own certificate to the client. With validation disabled, the client accepts this certificate and the attacker receives all traffic in cleartext: credentials, session tokens, payment data, health information, and any other sensitive content.

This pattern is extremely common in development codebases. Developers disable validation to work with self-signed certificates on local test servers and forget to re-enable it before shipping. Tools such as Burp Suite and Charles Proxy are explicitly designed to exploit this class of vulnerability to intercept mobile app traffic, and penetration testers routinely discover it in production applications.

Certificate pinning — associating the server's specific public key with the application — provides an additional layer of defence beyond standard chain validation. Even if an attacker obtains a certificate from a trusted CA, pinning will reject it unless the public key matches the pinned value.

## What Gets Flagged

```swift
// FLAGGED: URLCredential(trust:) unconditionally accepts any certificate
func urlSession(_ session: URLSession,
                didReceive challenge: URLAuthenticationChallenge,
                completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
    let credential = URLCredential(trust: challenge.protectionSpace.serverTrust!)
    completionHandler(.useCredential, credential) // FLAGGED
}

// FLAGGED: completion handler accepts credential without verifying serverTrust
func urlSession(_ session: URLSession,
                task: URLSessionTask,
                didReceive challenge: URLAuthenticationChallenge,
                completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
    completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))
}

// FLAGGED: Alamofire server trust evaluation disabled
let manager = Session(serverTrustManager: ServerTrustManager(evaluators: [
    "api.example.com": DisabledTrustEvaluator()  // FLAGGED
]))
```

## Remediation

1. **Perform proper server trust evaluation in `URLSession` authentication challenge delegates.** Validate the certificate chain against system-trusted roots before calling `completionHandler(.useCredential, ...)`.

   ```swift
   // SAFE: proper server trust evaluation
   func urlSession(_ session: URLSession,
                   didReceive challenge: URLAuthenticationChallenge,
                   completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
       guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
             let serverTrust = challenge.protectionSpace.serverTrust else {
           completionHandler(.cancelAuthenticationChallenge, nil)
           return
       }

       // Evaluate the server trust using system policy
       var error: CFError?
       let isValid = SecTrustEvaluateWithError(serverTrust, &error)

       if isValid {
           completionHandler(.useCredential, URLCredential(trust: serverTrust))
       } else {
           completionHandler(.cancelAuthenticationChallenge, nil)
       }
   }
   ```

2. **Use Alamofire's `PinnedCertificatesTrustEvaluator` or `PublicKeysTrustEvaluator` for certificate pinning.** This validates both the chain and the specific certificate or key.

   ```swift
   // SAFE: Alamofire with certificate pinning
   let evaluators: [String: ServerTrustEvaluating] = [
       "api.example.com": PinnedCertificatesTrustEvaluator(
           certificates: Bundle.main.af.certificates,
           acceptSelfSignedCertificates: false,
           performDefaultValidation: true,
           validateHost: true
       )
   ]
   let session = Session(serverTrustManager: ServerTrustManager(evaluators: evaluators))
   ```

3. **Remove test-only validation bypasses before merging to main.** Use build flags or separate test configurations so that certificate validation bypasses used for local development are never included in production builds.

   ```swift
   // SAFE: bypass only in debug builds
   #if DEBUG
   let evaluators: [String: ServerTrustEvaluating] = [
       "localhost": DisabledTrustEvaluator()
   ]
   #else
   let evaluators: [String: ServerTrustEvaluating] = [
       "api.example.com": PinnedCertificatesTrustEvaluator()
   ]
   #endif
   ```

4. **Enable App Transport Security (ATS).** Ensure `NSAllowsArbitraryLoads` is not set to `true` in `Info.plist`. ATS enforces minimum TLS requirements at the OS level as an additional safety net.

## References

- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)
- [OWASP Mobile Security Testing Guide – MSTG-NETWORK-3 (Certificate Validation)](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0064/)
- [Apple – Preventing Insecure Network Connections (App Transport Security)](https://developer.apple.com/documentation/bundleresources/information_property_list/nsapptransportsecurity)
- [Apple – SecTrustEvaluateWithError](https://developer.apple.com/documentation/security/2980705-sectrustevaluatewitherror)
- [Alamofire – Security Documentation](https://github.com/Alamofire/Alamofire/blob/master/Documentation/AdvancedUsage.md#security)
- [CAPEC-94: Adversary in the Middle (CAPEC-94)](https://capec.mitre.org/data/definitions/94.html)
- [MITRE ATT&CK T1557 – Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)
