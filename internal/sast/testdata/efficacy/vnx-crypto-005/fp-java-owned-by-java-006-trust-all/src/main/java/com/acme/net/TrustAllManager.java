package com.acme.net;

import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class TrustAllManager implements X509TrustManager {

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }

    public static SSLContext insecureContext() throws Exception {
        TrustManager[] managers = new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(X509Certificate[] c, String a) {}
                public void checkServerTrusted(X509Certificate[] c, String a) {}
            }
        };
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, managers, new java.security.SecureRandom());
        return ctx;
    }

    static class Wrapped implements X509TrustManager {
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        public void checkClientTrusted(X509Certificate[] c, String a) {}

        public void checkServerTrusted(X509Certificate[] chain,
                                       String authType)
                throws java.security.cert.CertificateException {
            // accept everything
        }
    }
}
