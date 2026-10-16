package com.acme.tls;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;

public class Names {
    // never use NoopHostnameVerifier or (h, s) -> true in production
    private static final String WARNING = "AllowAllHostnameVerifier is unsafe";

    static class TrustAllCerts {
        String describe() { return WARNING; }
    }

    static class Delegating implements X509TrustManager {
        private final X509TrustManager d;
        Delegating(X509TrustManager d) { this.d = d; }
        public void checkClientTrusted(X509Certificate[] c, String a) throws CertificateException {
            d.checkClientTrusted(c, a);
        }
        public void checkServerTrusted(X509Certificate[] c, String a) throws CertificateException {
            d.checkServerTrusted(c, a);
        }
        public X509Certificate[] getAcceptedIssuers() { return d.getAcceptedIssuers(); }
    }
}
