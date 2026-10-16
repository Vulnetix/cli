package com.acme.web;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuditFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(AuditFilter.class);

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
~>        log.info("Authorization: {}", request.getHeader("Authorization"));
~>        log.debug("params {}", request.getParameterMap());
~>        log.debug("cookies {}", Arrays.toString(request.getCookies()));
        chain.doFilter(req, res);
    }
}
