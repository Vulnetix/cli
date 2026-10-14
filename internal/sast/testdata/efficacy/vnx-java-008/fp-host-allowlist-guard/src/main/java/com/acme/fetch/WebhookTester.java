package com.acme.fetch;

import java.net.URL;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;

public class WebhookTester {
    private static final Set<String> ALLOWED_HOSTS = Set.of("hooks.partner.example");

    public void test(HttpServletRequest request) throws Exception {
        String hook = request.getParameter("hook");
        URL parsed = new java.net.URI(hook).toURL();
        if (!ALLOWED_HOSTS.contains(parsed.getHost())) {
            throw new SecurityException("host not allowed");
        }
        String target = request.getParameter("target");
        if (target.startsWith("https://hooks.partner.example/")) {
            new URL(target).openStream().close();
        }
    }
}
