package com.acme.repo;

import java.util.concurrent.ExecutorService;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;

public class RemoteClient {
    private final CloseableHttpClient httpclient;
    private final ExecutorService pool;

    public RemoteClient(CloseableHttpClient c, ExecutorService p) { this.httpclient = c; this.pool = p; }

    public void fetch(String host, String path) throws Exception {
        HttpGet get = new HttpGet("https://" + host + "/" + path);
        httpclient.execute(get);
        pool.execute(() -> System.out.println("fetched " + host + path));
        String label = "selected: " + path;
        System.out.println(label);
    }
}
