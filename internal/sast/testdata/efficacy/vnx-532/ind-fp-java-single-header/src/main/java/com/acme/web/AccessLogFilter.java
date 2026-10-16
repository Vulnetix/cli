package com.acme.web;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AccessLogFilter {

    private static final Logger log = LoggerFactory.getLogger(AccessLogFilter.class);

    public void record(HttpServletRequest request) {
        log.info("{} {} ua={}", request.getMethod(), request.getRequestURI(), request.getHeader("User-Agent"));
        log.info("trace={}", request.getHeader("X-Request-Id"));
        boolean hasAuth = request.getHeader("Authorization") != null;
        log.debug("auth present={}", hasAuth);
        log.debug("param count={}", request.getParameterMap().size());
    }
}
