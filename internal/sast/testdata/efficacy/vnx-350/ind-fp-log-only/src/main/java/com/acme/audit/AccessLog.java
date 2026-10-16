package com.acme.audit;

import javax.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AccessLog {
    private static final Logger log = LoggerFactory.getLogger(AccessLog.class);

    public void record(HttpServletRequest request) {
        String host = request.getRemoteHost();
        log.info("request from {} ({})", host, request.getRemoteAddr());
        if (host == null || host.isEmpty()) {
            log.debug("no reverse name");
        }
    }
}
