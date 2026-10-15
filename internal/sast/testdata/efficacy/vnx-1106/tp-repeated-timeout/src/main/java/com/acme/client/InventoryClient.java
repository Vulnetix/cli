package com.acme.client;

import java.net.HttpURLConnection;
import java.net.URL;

public class InventoryClient {

    public HttpURLConnection open(URL url) throws Exception {
        HttpURLConnection c = (HttpURLConnection) url.openConnection();
~>        c.setConnectTimeout(15000);
~>        c.setReadTimeout(15000);
        return c;
    }

    public void retry(Runnable r) throws InterruptedException {
        for (int i = 0; i < 3; i++) {
            r.run();
~>            Thread.sleep(15000);
        }
    }
}
