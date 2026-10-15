package com.acme;

import java.net.HttpURLConnection;
import java.net.URL;

public class Remote {
    public int call(String token) throws Exception {
~>        URL url = new URL("http://partner.acme-corp.com/api/v2/status");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestProperty("Authorization", "Bearer " + token);
        return conn.getResponseCode();
    }
}
