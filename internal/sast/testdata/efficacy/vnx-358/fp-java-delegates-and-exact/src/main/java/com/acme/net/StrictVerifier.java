package com.acme.net;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;

public class StrictVerifier implements HostnameVerifier {
    private final HostnameVerifier delegate = HttpsURLConnection.getDefaultHostnameVerifier();

    @Override
    public boolean verify(String hostname, SSLSession session) {
        return hostname.endsWith(".acme.com") && delegate.verify(hostname, session);
    }
}

class ExactVerifier implements HostnameVerifier {
    public boolean verify(String hostname, SSLSession session) {
        return "api.acme.com".equals(hostname) && session.getPeerHost().equals(hostname);
    }
}

class Paths {
    static boolean isApi(String path) {
        return path.startsWith("/api/") || path.endsWith(".json");
    }
}
