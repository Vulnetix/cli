package com.acme.http;

import java.net.http.HttpClient;
import java.time.Duration;

public class ClientFactory {

    private volatile HttpClient client;

    public HttpClient client() {
        HttpClient result = client;
        if (result == null) {
            synchronized (this) {
                result = client;
                if (result == null) {
                    client = result = HttpClient.newBuilder()
                            .connectTimeout(Duration.ofSeconds(5))
                            .build();
                }
            }
        }
        return result;
    }
}
