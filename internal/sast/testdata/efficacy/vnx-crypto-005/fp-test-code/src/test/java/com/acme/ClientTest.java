package com.acme;

import javax.net.ssl.HttpsURLConnection;

public class ClientTest {
    void setUp() {
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
    }
}
