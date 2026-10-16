package com.acme;

import javax.servlet.http.*;
import java.net.URI;

public class SafeFilter {
    void check(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String path = URI.create(request.getRequestURI()).normalize().getPath();
        if (path.toLowerCase().startsWith("/admin") && !isAdmin(request)) {
            response.sendError(403);
        }
        if (request.getServletPath().equals("/admin")) { response.sendError(403); }
    }
}
