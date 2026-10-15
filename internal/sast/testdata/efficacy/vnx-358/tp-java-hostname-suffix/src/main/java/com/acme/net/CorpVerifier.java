package com.acme.net;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

public class CorpVerifier implements HostnameVerifier {
    @Override
    public boolean verify(String hostname, SSLSession session) {
~>        return hostname.endsWith("acme.com");
    }
}

class LooseVerifier implements HostnameVerifier {
    public boolean verify(final String host, final SSLSession sslSession) {
        String peer = sslSession.getPeerHost();
~>        if (host.contains("internal")) {
            return true;
        }
        return false;
    }
}
