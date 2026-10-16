package com.acme;

import java.net.HttpURLConnection;

public class Client {
    void configure(HttpURLConnection c) throws Exception {
~>        c.setConnectTimeout(15000);
~>        c.setReadTimeout(15000);
        c.setRequestMethod("GET");
    }

    void backoff() throws InterruptedException {
~>        Thread.sleep(15000);
    }
}
