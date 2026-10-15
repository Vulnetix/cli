package com.acme.proxy;

import java.net.URI;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.client.RestTemplate;

public class SafePreview {
    private static final Set<String> ALLOWED_HOSTS = Set.of("cdn.acme.com", "images.acme.com");
    private final RestTemplate restTemplate = new RestTemplate();

    public String preview(HttpServletRequest request) {
        String link = request.getParameter("link");
        URI uri = URI.create(link);
        if (!"https".equals(uri.getScheme()) || !ALLOWED_HOSTS.contains(uri.getHost())) {
            throw new IllegalArgumentException("host not allowed");
        }
        return restTemplate.getForObject(uri, String.class);
    }
}
