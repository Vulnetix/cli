package com.acme.web;

import javax.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import @@sample:o[r]g[.][s]lf[4]j[.][L]og[g]er[F]ac[t]or[y]@@;

public class AuditFilter {
    private static final Logger LOG = LoggerFactory.getLogger(AuditFilter.class);

    public void audit(HttpServletRequest request) {
        String claimedRole = request.getHeader("X-Role");
        LOG.info("request claimed role {}", claimedRole);
        if (request.isUserInRole("admin")) {
            LOG.info("admin request");
        }
        // if ("admin".equals(request.getHeader("X-Role"))) { grant(); }
    }
}
