package com.acme.web;

import javax.servlet.http.*;

public class AdminFilter {
    boolean blocked(HttpServletRequest request) {
        String path = java.net.URI.create(request.getRequestURI()).normalize().getPath().toLowerCase();
        if (path.startsWith("/admin")) {
            return true;
        }
        String servletPath = request.getServletPath();
        return false;
    }

    void log(HttpServletRequest request) {
        if (request.getRequestURI().startsWith("/static")) {
            cache.hit();
        }
    }
}
