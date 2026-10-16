package com.acme.net;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

public class InternalHostVerifier implements HostnameVerifier {
    @Override
    public boolean verify(String hostname, SSLSession session) {
        if (hostname == null) {
            return false;
        }
~>        return hostname.endsWith("internal.acme.io");
    }
}
