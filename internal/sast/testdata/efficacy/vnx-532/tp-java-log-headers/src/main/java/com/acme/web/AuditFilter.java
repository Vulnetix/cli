package com.acme.web;

import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.RequestHeader;

public class AuditFilter {
    public void doFilter(HttpServletRequest request) {
~>        log.debug("Authorization: {}", request.getHeader("Authorization"));
~>        logger.info("params {}", request.getParameterMap());
    }

    public String handle(@RequestHeader HttpHeaders headers, @RequestBody String body) {
~>        LOG.info("headers {}", headers);
        return "ok";
    }
}
