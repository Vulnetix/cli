package com.acme.net;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;

public class ScopedVerifier implements HostnameVerifier {
    private final HostnameVerifier delegate = HttpsURLConnection.getDefaultHostnameVerifier();

    @Override
    public boolean verify(String hostname, SSLSession session) {
        return hostname.endsWith(".acme.com") && delegate.verify(hostname, session);
    }
}
