package com.acme.http;

import org.apache.http.conn.ssl.NoopHostnameVerifier;

public class Notes {
    // conn.setHostnameVerifier((hostname, session) -> true) disables checks.
    private static final String BAD = "NoopHostnameVerifier.INSTANCE and ALLOW_ALL_HOSTNAME_VERIFIER are banned";

    /*
     * public void checkServerTrusted(X509Certificate[] c, String a) {}
     */
    public String bad() {
        return BAD;
    }
}
