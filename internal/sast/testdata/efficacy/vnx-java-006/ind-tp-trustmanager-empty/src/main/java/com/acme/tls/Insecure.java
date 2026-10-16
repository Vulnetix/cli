package com.acme.tls;

import java.security.cert.X509Certificate;
import javax.net.ssl.*;

public class Insecure {
    public SSLContext ctx() throws Exception {
        TrustManager[] tm = new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                public void checkClientTrusted(X509Certificate[] c, String a) {}
~>                public void checkServerTrusted(X509Certificate[] c, String a) {}
            }
        };
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, tm, new java.security.SecureRandom());
        return sc;
    }
}
