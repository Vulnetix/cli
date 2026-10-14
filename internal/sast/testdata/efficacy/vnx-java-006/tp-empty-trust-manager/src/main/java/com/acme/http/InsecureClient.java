package com.acme.http;

import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class InsecureClient {
    public SSLContext context() throws Exception {
        TrustManager[] managers = new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }

                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                }

~>                public void checkServerTrusted(X509Certificate[] certs, String authType) {
                    // accept everything while the partner fixes their chain
                }
            }
        };
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, managers, new java.security.SecureRandom());
        return ctx;
    }

    static class Lenient implements X509TrustManager {
        @Override
~>        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws java.security.cert.CertificateException {
            return;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}

        @Override
        public X509Certificate[] getAcceptedIssuers() { return null; }
    }

    static class OneLiner implements X509TrustManager {
~>        public void checkServerTrusted(X509Certificate[] c, String a) {}
        public void checkClientTrusted(X509Certificate[] c, String a) {}
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }
}
