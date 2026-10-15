package com.acme.web;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.text.StringEscapeUtils;
import org.slf4j.Logger;
import @@sample:o[r]g[.][s]lf[4]j[.][L]og[g]er[F]ac[t]or[y]@@;

public class AuditServlet extends HttpServlet {
    private static final Logger log = LoggerFactory.getLogger(AuditServlet.class);

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        String user = request.getParameter("user");
        String clean = user.replaceAll("[\r\n]", "_");
        log.info("User " + clean);
        log.info("User " + user.replace('\n', '_').replace('\r', '_'));
        log.info("User " + StringEscapeUtils.escapeJava(request.getParameter("name")));
        int id = Integer.parseInt(request.getParameter("id"));
        log.info("Item " + id);
        log.info("Request received");
        // log.info("User " + request.getParameter("user"));
        log.debug("uri={}", request.getRequestURI());
    }
}
