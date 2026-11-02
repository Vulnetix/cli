---
title: "VNX-SWIFT-004 – Swift TLS Certificate Validation Disabled in URLSession or Alamofire"
description: "Detects Swift code that accepts a server certificate without validating it: URLCredential(trust:) built without evaluating or pinning the trust, Alamofire DisabledTrustEvaluator/.disableEvaluation, kCFStreamSSLValidatesCertificateChain false, setAllowsAnyHTTPSCertificate, Starscream disableSSLCertValidation/allowSelfSigned, and a Network.framework verify block that always completes true."
---

## Overview

This rule reports Swift code that accepts a TLS server certificate without validating it:

1. `URLCredential(trust:)` built in a function that never evaluates or pins the trust before it (no `SecTrustEvaluateWithError`/`SecTrustEvaluate`, `evaluator.evaluate(...)`, certificate or public-key comparison, or call to a validate/verify/check/pin helper). This is how a `URLSession` or `NSURLConnection` auth-challenge delegate trusts every certificate. A host-name comparison is not validation.
2. Alamofire `DisabledTrustEvaluator()` / `DisabledEvaluator()` and the Alamofire 4 `ServerTrustPolicy` `.disableEvaluation`.
3. `kCFStreamSSLValidatesCertificateChain` set to false on a stream.
4. `NSURLRequest.setAllowsAnyHTTPSCertificate(true, forHost:)`.
5. A `sec_protocol_options_set_verify_block` whose block completes with `true` without evaluating the trust.

It does not report `URLCredential(trust:)` after the trust was evaluated or pinned, `URLCredential(user:password:)`, `.performDefaultHandling`, pinned or default Alamofire evaluators, the evaluator class declarations, string literals, comments and test files.

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
    let credential = URLCredential(trust: challenge.protectionSpace.serverTrust!) // FLAGGED
    completionHandler(.useCredential, credential)
}

// FLAGGED: completion handler accepts credential without verifying serverTrust
func urlSession(_ session: URLSession,
                task: URLSessionTask,
                didReceive challenge: URLAuthenticationChallenge,
                completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
    completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))
}

// FLAGGED: Starscream WebSocket accepting any or self-signed certificates
socket.disableSSLCertValidation = true
let pinner = FoundationSecurity(allowSelfSigned: true)

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
