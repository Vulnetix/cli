package com.acme.web;

import javax.servlet.http.HttpServletRequest;

public class DebugController {
    public boolean debug(HttpServletRequest request) {
        String mode = request.getParameter("mode");
        return "verbose".equals(mode) || "true".equals(request.getHeader("X-Debug"));
    }
}
