package com.acme.http;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;

public class LegacyHttps {
    static {
        HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
            @Override
~>            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        });
    }
}
