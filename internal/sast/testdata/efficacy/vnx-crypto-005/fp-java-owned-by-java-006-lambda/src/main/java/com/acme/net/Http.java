package com.acme.net;

import javax.net.ssl.HttpsURLConnection;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.HttpClients;

public class Http {
    static {
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
    }

    Object client() {
        return HttpClients.custom().setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE).build();
    }
}
