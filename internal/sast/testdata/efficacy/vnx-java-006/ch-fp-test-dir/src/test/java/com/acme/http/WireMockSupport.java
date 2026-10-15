package com.acme.http;

import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;

public class WireMockSupport {
    public static org.apache.http.impl.client.CloseableHttpClient client() throws Exception {
        return HttpClients.custom()
                .setSSLContext(SSLContexts.custom().loadTrustMaterial(null, TrustAllStrategy.INSTANCE).build())
                .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                .build();
    }
}
