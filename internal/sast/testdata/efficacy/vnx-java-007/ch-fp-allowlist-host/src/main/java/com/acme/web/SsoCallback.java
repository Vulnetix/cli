package com.acme.web;

import java.net.URI;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SsoCallback {
    private static final Set<String> ALLOWED_HOSTS = Set.of("app.acme.com", "admin.acme.com");

    public void done(HttpServletRequest request, HttpServletResponse response) throws java.io.IOException {
        String returnTo = request.getParameter("return_to");
        URI uri = URI.create(returnTo);
        if (!ALLOWED_HOSTS.contains(uri.getHost())) {
            response.sendError(400);
            return;
        }
        response.sendRedirect(returnTo);
    }
}
