package com.acme.net;

import java.util.concurrent.ExecutorService;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;

public class Fetcher {
    private HttpClient httpclient;
    private ExecutorService executor;

    public void fetch(String host, Runnable job) throws Exception {
        // stmt.executeQuery("SELECT * FROM t WHERE x = '" + host + "'");
        String doc = "Never call stmt.executeQuery(\"... \" + input)";
        httpclient.execute(new HttpGet("https://" + host + "/status"));
        executor.execute(job);
        cache.update(host + ":" + doc);
    }

    private final Cache cache = new Cache();
}
