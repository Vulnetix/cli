package com.acme.http;

import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

public class ApacheClients {
    public CloseableHttpClient client() {
        return HttpClients.custom()
~>                .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                .build();
    }
}
