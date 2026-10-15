package com.acme.client;

import java.net.URL;

public class LegacyClient {
    String endpoint(String host, String user, String password) throws Exception {
~>        URL url = new URL("https://" + host + "/auth?user=" + user + "&password=" + password);
        return url.toString();
    }

    String fmt(String key) {
~>        return String.format("https://api.example.com/q?api_key=%s", key);
    }
}
