package com.acme.web;

import javax.servlet.http.HttpServletRequest;

public class AdminController {
    public String purge(HttpServletRequest request) {
        String clientIp = request.getHeader("X-Forwarded-For");
~>        if ("127.0.0.1".equals(clientIp)) {
            cache.purgeAll();
            return "ok";
        }
~>        if (request.getHeader("X-Real-IP").startsWith("10.")) {
            return "internal";
        }
        return "denied";
    }
}
