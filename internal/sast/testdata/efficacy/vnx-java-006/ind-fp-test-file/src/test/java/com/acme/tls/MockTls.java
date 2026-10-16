package com.acme.tls;

import javax.net.ssl.HttpsURLConnection;

public class MockTls {
    void relax(HttpsURLConnection conn) {
        conn.setHostnameVerifier((hostname, session) -> true);
    }
}
