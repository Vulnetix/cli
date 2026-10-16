package com.acme.fetch;

import java.net.URI;
import java.net.URL;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;

public class Guard {
    private static final Set<String> HOSTS = Set.of("api.example.com", "cdn.example.com");

    public Object fetch(HttpServletRequest req) throws Exception {
        String u = req.getParameter("u");
        URI uri = URI.create(u);
        if (!HOSTS.contains(uri.getHost())) {
            throw new IllegalArgumentException("host not allowed");
        }
        return new URL(u).openStream();
    }
}
