package com.acme.net;

import java.util.Set;
import javax.servlet.http.HttpServletRequest;

public final class TrustedIp {
    private static final Set<String> TRUSTED_PROXIES = Set.of("10.0.0.5");

    public static String resolve(HttpServletRequest request) {
        String peer = request.getRemoteAddr();
        if (TRUSTED_PROXIES.contains(peer)) {
            String ip = request.getHeader("X-Real-IP");
            return ip != null ? ip : peer;
        }
        return peer;
    }
}
