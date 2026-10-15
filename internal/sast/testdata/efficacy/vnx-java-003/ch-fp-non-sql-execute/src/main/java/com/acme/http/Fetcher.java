package com.acme.http;

import java.util.concurrent.ExecutorService;
import javax.servlet.http.HttpServletRequest;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;

public class Fetcher {
    private CloseableHttpClient httpClient;
    private ExecutorService executor;
    private org.slf4j.Logger log;

    public void fetch(HttpServletRequest request) throws Exception {
        String path = request.getParameter("path");
        httpClient.execute(new HttpGet("https://api.acme.com/" + path));
        executor.execute(() -> log.info("fetched " + path));
        log.debug("executeQuery(\"SELECT * FROM t WHERE id=\" + path)");
        // stmt.executeQuery("SELECT * FROM t WHERE p = '" + path + "'");
    }
}
