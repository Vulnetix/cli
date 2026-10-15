package com.example;

import java.net.URI;
import java.util.Set;

public class Origins {
    private static final Set<String> ALLOWED = Set.of("https://acme.com", "https://app.acme.com");

    boolean allowed(String origin) {
        return ALLOWED.contains(origin);
    }

    boolean sameSite(String url) {
        String host = URI.create(url).getHost();
        return "acme.com".equals(host) || host.endsWith(".acme.com");
    }
}
