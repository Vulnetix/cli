package com.acme.sso;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class LegacyBridge {

    private final HttpClient http = HttpClient.newHttpClient();
    private final String baseUrl;

    public LegacyBridge(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public String profile(String sessionId) throws Exception {
~>        String url = baseUrl + "/profile?sessionid=" + sessionId;
        HttpRequest req = HttpRequest.newBuilder(URI.create(url)).GET().build();
        return http.send(req, HttpResponse.BodyHandlers.ofString()).body();
    }
}
