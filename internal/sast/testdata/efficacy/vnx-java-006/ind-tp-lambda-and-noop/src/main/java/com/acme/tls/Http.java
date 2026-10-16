package com.acme.tls;

import javax.net.ssl.HttpsURLConnection;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;

public class Http {
    void a(HttpsURLConnection conn) {
~>        conn.setHostnameVerifier((hostname, session) -> true);
    }

    SSLConnectionSocketFactory b(javax.net.ssl.SSLContext ctx) {
~>        return new SSLConnectionSocketFactory(ctx, NoopHostnameVerifier.INSTANCE);
    }
}
