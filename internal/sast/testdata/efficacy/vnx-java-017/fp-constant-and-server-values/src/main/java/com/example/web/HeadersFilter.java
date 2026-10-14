package com.example.web;

import java.io.IOException;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class HeadersFilter {
    private static final String CSP = "default-src 'self'";

    public void apply(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String user = request.getParameter("user");
        audit(user);
        response.setHeader("Content-Security-Policy", CSP);
        response.setHeader("X-Request-Id", UUID.randomUUID().toString());
        response.addHeader("Cache-Control", "no-store");
        String ctx = request.getContextPath();
        response.sendRedirect(ctx + "/login");
        Object role = request.getAttribute("role");
        response.setHeader("X-Role", String.valueOf(role));
    }

    private void audit(String u) {}
}
