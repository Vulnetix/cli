package com.acme.web;

public class Access {
    void log(javax.servlet.http.HttpServletRequest request) {
        log.info("UA: {}", request.getHeader("User-Agent"));
        log.info("uri={}", request.getRequestURI());
    }
}
