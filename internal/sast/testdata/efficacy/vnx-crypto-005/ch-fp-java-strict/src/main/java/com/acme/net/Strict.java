package com.acme.net;

import java.security.cert.CertificateException;
import @@sample:j[a]va[.]se[c]ur[i]ty[.]ce[r]t[.][X]50[9]Ce[r]ti[f]ic[a]te@@;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

public class Strict {
    static HostnameVerifier pinned = new HostnameVerifier() {
        @Override
        public boolean verify(String hostname, SSLSession session) {
            return "api.example.com".equals(hostname);
        }
    };

    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (chain == null || chain.length == 0) {
            throw new CertificateException("empty chain");
        }
        Pins.check(chain[0]);
    }
}
