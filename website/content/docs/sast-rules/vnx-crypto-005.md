---
title: "VNX-CRYPTO-005 – TLS Certificate Validation Disabled"
description: "Detects code that disables TLS certificate verification in Python, Node.js, Go, and Java, exposing connections to man-in-the-middle attacks."
---

## Overview

This rule detects code that explicitly disables TLS/SSL certificate validation. When certificate verification is turned off, the TLS handshake completes without confirming the server's identity, meaning an attacker positioned between the client and server can intercept and modify all traffic. This is one of the most severe transport-layer security misconfigurations, captured by CWE-295 (Improper Certificate Validation).

**Severity:** High | **CWE:** [CWE-295 – Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

## Why This Matters

TLS certificate validation is the foundation of trust on the internet. The TLS handshake proves that you are talking to `api.example.com` and not an attacker's server. When you set `verify=False`, `InsecureSkipVerify: true`, or `rejectUnauthorized: false`, you strip out this proof entirely — the encrypted channel still exists, but you have no way to know who is on the other end.

In corporate and cloud environments, man-in-the-middle attacks via rogue Wi-Fi, ARP spoofing, BGP hijacking, or compromised proxies are realistic threats. The 2014 "goto fail" Apple TLS bug and numerous mobile application vulnerabilities discovered via Burp Suite interceptions all stem from this class of issue. Sensitive API calls made over a "verified=False" connection leak authentication tokens, session cookies, and customer data to any network observer.

Developers often disable verification to deal with self-signed certificates in development or to bypass corporate MITM proxies. These workarounds should never reach production code, but they frequently do. CAPEC-94 (Man in the Middle Attack) describes the full attack scenario.

## What Gets Flagged

The rule matches the most common verification-bypass patterns across Python, Node.js, Go, and Java:

```python
# FLAGGED: requests with SSL verification disabled
import requests
response = requests.get("https://api.example.com", verify=False)

# FLAGGED: ssl context with certificate checking disabled
import ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
```

```go
// FLAGGED: Go HTTP client with InsecureSkipVerify
tr := &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}
```

```javascript
// FLAGGED: Node.js HTTPS with rejectUnauthorized disabled
https.request({ rejectUnauthorized: false }, ...);

// FLAGGED: Node.js environment variable bypass
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
```

## Remediation

1. **Remove the bypass and fix the underlying certificate problem.** Disabled certificate verification is almost always a symptom of a certificate management problem. The correct fix is to install a valid certificate, not to turn off the check.

2. **For self-signed or internal CA certificates, add the CA to the trust store.** Do not disable all verification — instead, configure the HTTP client to trust your internal CA.

   ```python
   # SAFE: trust an internal CA certificate bundle
   import requests
   response = requests.get("https://internal.example.com", verify="/path/to/internal-ca.pem")
   ```

   ```go
   // SAFE: Go client with custom CA pool
   caCert, _ := os.ReadFile("internal-ca.pem")
   caCertPool := x509.NewCertPool()
   caCertPool.AppendCertsFromPEM(caCert)
   tr := &http.Transport{
       TLSClientConfig: &tls.Config{RootCAs: caCertPool},
   }
   client := &http.Client{Transport: tr}
   ```

3. **For Node.js, never set `NODE_TLS_REJECT_UNAUTHORIZED=0` in code.** If it must be set in a test environment, add a CI check that ensures it is not present in production configurations.

4. **In Java, use a `KeyStore` with your trusted certificates** rather than implementing a trust manager that accepts all certificates.

   ```java
   // SAFE: custom TrustManager backed by a proper KeyStore
   KeyStore ks = KeyStore.getInstance("JKS");
   ks.load(new FileInputStream("truststore.jks"), password);
   TrustManagerFactory tmf = TrustManagerFactory.getInstance(
       TrustManagerFactory.getDefaultAlgorithm());
   tmf.init(ks);
   SSLContext ctx = SSLContext.getInstance("TLS");
   ctx.init(null, tmf.getTrustManagers(), null);
   ```

5. **Use environment-specific configuration.** If you genuinely need different behavior in development vs. production, gate the bypass on an environment variable that is never set in production, and add a CI check to catch it.

## References

- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)
- [CAPEC-94: Man in the Middle Attack](https://capec.mitre.org/data/definitions/94.html)
- [MITRE ATT&CK T1557 – Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)
- [OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
- [Python requests – SSL Cert Verification](https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification)
- [Go crypto/tls – InsecureSkipVerify](https://pkg.go.dev/crypto/tls#Config)
- [Node.js TLS documentation](https://nodejs.org/api/tls.html#tlscreatesecurecontextoptions)
