package com.acme.sync;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

public class ReportClient {

    public String fetch(String user, String password) throws IOException {
~>        HttpGet get = new HttpGet("http://reports.acme-corp.com/api/daily");
        String basic = Base64.getEncoder()
                .encodeToString((user + ":" + password).getBytes(StandardCharsets.UTF_8));
        get.setHeader("Authorization", "Basic " + basic);
        try (CloseableHttpClient client = HttpClients.createDefault();
             CloseableHttpResponse resp = client.execute(get)) {
            return new String(resp.getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
