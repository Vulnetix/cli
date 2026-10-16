package com.acme.net;

import java.util.Set;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

public class ExactVerifier implements HostnameVerifier {
    private static final Set<String> ALLOWED = Set.of("api.acme.com", "auth.acme.com");

    @Override
    public boolean verify(String hostname, SSLSession session) {
        if ("localhost".equals(hostname)) {
            return false;
        }
        return ALLOWED.contains(hostname);
    }
}
