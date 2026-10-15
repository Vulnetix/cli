package com.acme.auth;

import javax.servlet.http.HttpServletRequest;
import org.owasp.encoder.Encode;
import org.slf4j.Logger;
import @@sample:o[r]g[.][s]lf[4]j[.][L]og[g]er[F]ac[t]or[y]@@;

public class AuditService {
    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    public void record(HttpServletRequest request, User user) {
        log.info("audit for user id {}", user.getId());
        String q = request.getParameter("q");
        log.info("search {}", Encode.forJava(q));
        int n = Integer.parseInt(request.getParameter("n"));
        log.info("page size {}", n);
        String ref = request.getHeader("Referer").replaceAll("[\r\n]", "_");
        log.info("referer {}", ref);
        log.debug("request parameter names: {}", "q, n");
    }
}
