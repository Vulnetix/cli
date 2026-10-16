package com.acme;

import java.net.HttpURLConnection;

public class Client {
    private static final int TIMEOUT_MS = 15000;

    void configure(HttpURLConnection c) {
        c.setConnectTimeout(TIMEOUT_MS);
        c.setReadTimeout(TIMEOUT_MS);
    }

    void backoff() throws InterruptedException {
        Thread.sleep(TIMEOUT_MS);
    }
}
