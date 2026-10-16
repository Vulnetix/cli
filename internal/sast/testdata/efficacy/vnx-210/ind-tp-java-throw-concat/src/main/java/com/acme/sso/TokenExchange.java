package com.acme.sso;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class TokenExchange {
    private final HttpClient http = HttpClient.newHttpClient();

    public String exchange(String refreshToken) throws IOException, InterruptedException {
        HttpRequest req = TokenRequests.refresh(refreshToken);
        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) {
~>            throw new IllegalStateException("refresh failed (" + resp.statusCode() + ") for token " + refreshToken);
        }
        return resp.body();
    }
}
