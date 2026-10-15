package com.example.hooks;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public class WebhookProbe {
    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3))
            .build();

    public int probe(String target) throws IOException, InterruptedException {
        HttpRequest req = HttpRequest.newBuilder(URI.create(target))
                .timeout(Duration.ofSeconds(5))
                .build();
        return client.send(req, HttpResponse.BodyHandlers.discarding()).statusCode();
    }

    public byte[] legacy(String target) throws IOException {
        URL url = new URL(target);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setConnectTimeout(3000);
        conn.setReadTimeout(5000);
        try (InputStream in = conn.getInputStream()) {
            return in.readAllBytes();
        }
    }

    public String help() {
        return "Do not call url.openStream() here; it has no timeout.";
    }
}
