package com.example.geo;

import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.util.Scanner;

public class IpLookup {
    private final String base;

    public IpLookup(String base) {
        this.base = base;
    }

    public String country(String ip) throws IOException {
        URL endpoint = URI.create(base + "/country/" + ip).toURL();
~>        try (Scanner sc = new Scanner(endpoint.openStream(), "UTF-8")) {
            return sc.useDelimiter("\\A").next();
        }
    }
}
