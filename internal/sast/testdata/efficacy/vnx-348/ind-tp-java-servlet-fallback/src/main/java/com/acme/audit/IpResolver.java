package com.acme.audit;

import javax.servlet.http.HttpServletRequest;

public final class IpResolver {
    private IpResolver() {}

    public static String resolve(HttpServletRequest request) {
~>        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        return ip.split(",")[0].trim();
    }
}
