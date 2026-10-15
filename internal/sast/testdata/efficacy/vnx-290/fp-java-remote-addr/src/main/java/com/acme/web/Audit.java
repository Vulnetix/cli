package com.acme.web;

import javax.servlet.http.HttpServletRequest;

public class Audit {
    void record(HttpServletRequest request) {
        String ip = request.getRemoteAddr();
        if ("127.0.0.1".equals(ip)) {
            return;
        }
        String fwd = request.getHeader("X-Forwarded-For");
        if (fwd != null) {
            log.info("forwarded for {}", fwd);
        }
    }
}
