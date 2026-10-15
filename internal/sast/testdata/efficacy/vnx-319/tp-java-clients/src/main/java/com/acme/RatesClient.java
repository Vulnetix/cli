package com.acme;

import java.net.URI;
import java.net.URL;

public class RatesClient {
~>    private static final String ENDPOINT = "http://rates.fx-provider.com/api";

    public String fetch() throws Exception {
~>        URL url = new URL("http://rates.fx-provider.com/api/latest");
~>        HttpRequest req = HttpRequest.newBuilder(URI.create("http://rates.fx-provider.com/v2")).build();
~>        Request r = new Request.Builder().url("http://rates.fx-provider.com/v3").build();
        return null;
    }
}
