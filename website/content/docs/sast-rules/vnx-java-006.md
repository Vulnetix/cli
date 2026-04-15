---
title: "VNX-JAVA-006 – Insecure TLS Trust Manager"
description: "Detects Java TLS configurations that disable certificate validation via empty checkServerTrusted() implementations or always-true HostnameVerifier instances, enabling man-in-the-middle attacks."
---

## Overview

This rule detects two closely related patterns that render TLS completely ineffective: (1) an `X509TrustManager` whose `checkServerTrusted()` method has an empty body, meaning it performs no validation and silently accepts any certificate presented by any server; and (2) named patterns such as `ALLOW_ALL_HOSTNAME_VERIFIER`, `TrustAllCerts`, `TrustAll`, and `NullTrustManager` that signal a hostname verifier which always returns `true`. Both patterns are covered by CWE-295 (Improper Certificate Validation).

**Severity:** Critical | **CWE:** [CWE-295 – Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

## Why This Matters

TLS's security guarantees rest entirely on two checks: (a) the server's certificate is signed by a trusted certificate authority, and (b) the certificate's Common Name or Subject Alternative Names match the hostname the client intended to connect to. Disabling either check means that any attacker who can intercept the network traffic — on a shared Wi-Fi network, inside a corporate proxy, via BGP hijacking, or through a compromised DNS resolver — can silently substitute their own certificate. The client connects to the attacker's server, believing it is speaking to the intended destination. All traffic is decrypted, modified, and re-encrypted in a classic man-in-the-middle (MitM) position.

In a microservices environment, a MitM position between internal services means an attacker who has already breached one service can intercept API calls, steal JWT tokens, modify responses in flight, and exfiltrate sensitive data without triggering any TLS alarm. These patterns are commonly introduced during development ("I just need to bypass the self-signed certificate warning") and then forgotten in production code.

## What Gets Flagged

The rule matches two patterns. First, named trust-manager bypass classes:

```java
// FLAGGED: ALLOW_ALL_HOSTNAME_VERIFIER disables hostname checking
HttpsURLConnection.setDefaultHostnameVerifier(
    SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);

// FLAGGED: custom "trust all" verifier
HostnameVerifier allHostsValid = new HostnameVerifier() {
    public boolean verify(String hostname, SSLSession session) {
        return true;  // accepts any hostname
    }
};
```

Second, an empty `checkServerTrusted` implementation:

```java
// FLAGGED: empty body means no certificate validation occurs
TrustManager[] trustAllCerts = new TrustManager[] {
    new X509TrustManager() {
        public X509Certificate[] getAcceptedIssuers() { return null; }
        public void checkClientTrusted(X509Certificate[] certs, String authType) {}
        public void checkServerTrusted(X509Certificate[] certs, String authType) {}
        //                                                                       ^^ empty — flagged
    }
};
```

## Remediation

1. **Remove the custom trust manager entirely and rely on the JVM's built-in trust store.** The JVM ships with a curated CA bundle (`$JAVA_HOME/lib/security/cacerts`). If the server's certificate is issued by a public CA, no custom trust manager is required.

   ```java
   // SAFE: use the default SSL context — JVM validates certificates automatically
   HttpsURLConnection conn = (HttpsURLConnection) new URL(url).openConnection();
   // No custom SSLContext, no custom HostnameVerifier needed
   ```

2. **For self-signed or private CA certificates, load the CA into a custom trust store — do not disable validation.** Import the CA certificate into a `KeyStore`, then construct an `SSLContext` from it. This preserves full certificate chain and hostname validation while trusting your internal PKI.

   ```java
   // SAFE: trust a specific private CA certificate, validate everything else normally
   KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
   try (InputStream caStream = getClass().getResourceAsStream("/certs/internal-ca.jks")) {
       ks.load(caStream, "changeit".toCharArray());
   }
   TrustManagerFactory tmf = TrustManagerFactory.getInstance(
       TrustManagerFactory.getDefaultAlgorithm());
   tmf.init(ks);

   SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
   sslContext.init(null, tmf.getTrustManagers(), new SecureRandom());

   HttpsURLConnection conn = (HttpsURLConnection) new URL(url).openConnection();
   conn.setSSLSocketFactory(sslContext.getSocketFactory());
   // Default HostnameVerifier is used — hostname validation is intact
   ```

3. **Implement a real `X509TrustManager` if you need custom logic.** Delegate to the JVM's default `TrustManager` first, then apply additional constraints. Never leave `checkServerTrusted` empty.

   ```java
   // SAFE: extends default trust, adds extra constraint
   public class PinningTrustManager implements X509TrustManager {
       private final X509TrustManager defaultTm;

       public PinningTrustManager() throws Exception {
           TrustManagerFactory tmf = TrustManagerFactory.getInstance(
               TrustManagerFactory.getDefaultAlgorithm());
           tmf.init((KeyStore) null);
           this.defaultTm = (X509TrustManager) tmf.getTrustManagers()[0];
       }

       @Override
       public void checkServerTrusted(X509Certificate[] chain, String authType)
               throws CertificateException {
           defaultTm.checkServerTrusted(chain, authType);  // delegates — never empty
           // Optionally: pin to a specific leaf or intermediate cert
       }

       @Override
       public X509Certificate[] getAcceptedIssuers() {
           return defaultTm.getAcceptedIssuers();
       }

       @Override
       public void checkClientTrusted(X509Certificate[] chain, String authType)
               throws CertificateException {
           defaultTm.checkClientTrusted(chain, authType);
       }
   }
   ```

4. **Enforce a minimum TLS version.** Configure the `SSLContext` or server properties to require at least TLS 1.2 (`TLSv1.2`), preferably TLS 1.3.

5. **Use Spring's `RestTemplate` or `WebClient` with a proper `SSLContext`.** If you use Spring's HTTP client abstractions, configure an `HttpComponentsClientHttpRequestFactory` backed by an `SSLContext` built as above, rather than installing a JVM-wide bypass.

## References

- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)
- [CAPEC-94: Man in the Middle Attack](https://capec.mitre.org/data/definitions/94.html)
- [MITRE ATT&CK T1557 – Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)
- [OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
- [OWASP Certificate Pinning Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Pinning_Cheat_Sheet.html)
- [Java JSSE Reference Guide – Custom Trust Managers](https://docs.oracle.com/en/java/javase/21/security/java-secure-socket-extension-jsse-reference-guide.html)
- [OWASP ASVS V9 – Communication](https://owasp.org/www-project-application-security-verification-standard/)
