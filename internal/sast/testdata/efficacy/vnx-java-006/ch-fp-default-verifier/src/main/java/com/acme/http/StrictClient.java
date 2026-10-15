package com.acme.http;

import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.impl.client.HttpClients;

public class StrictClient {
    // Never use NoopHostnameVerifier.INSTANCE here.
    private static final String NOTE = "ALLOW_ALL_HOSTNAME_VERIFIER is forbidden";

    public org.apache.http.impl.client.CloseableHttpClient client() {
        return HttpClients.custom()
                .setSSLHostnameVerifier(new DefaultHostnameVerifier())
                .build();
    }
}
