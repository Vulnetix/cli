package com.acme.tls;

import java.security.KeyStore;
import javax.net.ssl.*;

public class Proper {
    public SSLContext ctx(KeyStore ks) throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        SSLContext sc = SSLContext.getInstance("TLSv1.3");
        sc.init(null, tmf.getTrustManagers(), null);
        return sc;
    }

    public HostnameVerifier pinned(String expected) {
        return (hostname, session) -> hostname.equalsIgnoreCase(expected);
    }
}
