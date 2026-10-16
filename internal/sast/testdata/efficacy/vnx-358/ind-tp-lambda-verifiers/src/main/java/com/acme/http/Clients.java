package com.acme.http;

import java.net.URL;
import javax.net.ssl.HttpsURLConnection;
import okhttp3.OkHttpClient;

public final class Clients {
    public static OkHttpClient partnerClient() {
        return new OkHttpClient.Builder()
~>            .hostnameVerifier((hostname, session) -> hostname.contains("partner-api"))
            .build();
    }

    public static HttpsURLConnection open(URL url) throws Exception {
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
~>        conn.setHostnameVerifier((host, sslSession) -> host.startsWith("api."));
        return conn;
    }
}
