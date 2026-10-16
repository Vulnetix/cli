package com.acme.web;

import javax.servlet.http.HttpServletRequest;

public final class LocalOnly {
    private LocalOnly() {}

    public static boolean fromLoopback(HttpServletRequest request) {
        String addr = request.getRemoteAddr();
        return "127.0.0.1".equals(addr) || "::1".equals(addr);
    }
}
