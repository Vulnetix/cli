package com.acme.legacy;

import java.net.HttpURLConnection;
import java.net.URL;

public class Client {
    public int call(String token) throws Exception {
~>        HttpURLConnection conn = (HttpURLConnection) new URL("http://legacy.acme-corp.net/api/orders").openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Authorization", "Bearer " + token);
        return conn.getResponseCode();
    }
}
