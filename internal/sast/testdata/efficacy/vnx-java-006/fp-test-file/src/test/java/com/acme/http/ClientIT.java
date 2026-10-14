package com.acme.http;

import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.HttpClients;

public class ClientIT {
    void localServer() {
        HttpClients.custom().setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE).build();
    }
}
