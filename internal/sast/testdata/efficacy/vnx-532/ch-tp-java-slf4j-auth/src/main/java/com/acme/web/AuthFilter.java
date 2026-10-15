package com.acme.web;

import javax.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import @@sample:o[r]g[.][s]lf[4]j[.][L]og[g]er[F]ac[t]or[y]@@;

public class AuthFilter {
    private static final Logger log = LoggerFactory.getLogger(AuthFilter.class);

    void check(HttpServletRequest request) {
~>        log.debug("Auth header: {}", request.getHeader("Authorization"));
    }
}
