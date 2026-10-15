package com.acme;

import javax.servlet.http.HttpServletRequest;

public final class IpUtil {
    public static String clientIp(HttpServletRequest request) {
~>        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        return ip.split(",")[0].trim();
    }
}
