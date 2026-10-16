package com.acme.tls;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;

public class Verifier {
    public void install() {
        HostnameVerifier all = new HostnameVerifier() {
            @Override
~>            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        };
        HttpsURLConnection.setDefaultHostnameVerifier(all);
    }
}
