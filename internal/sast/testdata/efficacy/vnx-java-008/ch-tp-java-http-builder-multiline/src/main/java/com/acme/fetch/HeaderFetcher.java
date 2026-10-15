package com.acme.fetch;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import javax.servlet.http.HttpServletRequest;

public class HeaderFetcher {
    private final HttpClient client = HttpClient.newHttpClient();

    public String fetch(HttpServletRequest req) throws Exception {
        String endpoint = req.getHeader("X-Callback");
        HttpRequest request = HttpRequest.newBuilder()
~>                .uri(URI.create(endpoint))
                .GET()
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString()).body();
    }
}
