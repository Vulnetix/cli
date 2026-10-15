package com.acme.client;

import java.net.HttpURLConnection;
import java.net.URL;

public class InventoryClient {

    private static final int TIMEOUT_MS = 15000;
    static final long ONE_DAY_MS = 86400000L;

    public HttpURLConnection open(URL url) throws Exception {
        HttpURLConnection c = (HttpURLConnection) url.openConnection();
        c.setConnectTimeout(TIMEOUT_MS);
        c.setReadTimeout(TIMEOUT_MS);
        Thread.sleep(TIMEOUT_MS);
        return c;
    }

    public boolean expired(long age) {
        return age > ONE_DAY_MS;
    }
}
