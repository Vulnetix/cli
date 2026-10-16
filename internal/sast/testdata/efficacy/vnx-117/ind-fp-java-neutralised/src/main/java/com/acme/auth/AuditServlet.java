package com.acme.auth;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.text.StringEscapeUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuditServlet extends HttpServlet {
    private static final Logger log = LoggerFactory.getLogger(AuditServlet.class);

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String user = request.getParameter("user");
        String safeUser = user.replaceAll("[\r\n]", "_");
        log.info("Audit view by " + safeUser);
        log.info("Path {}", request.getRequestURI());
        log.info("Agent " + StringEscapeUtils.escapeJava(request.getHeader("User-Agent")));
        int page = Integer.parseInt(request.getParameter("page"));
        log.debug("page " + page);
        response.setStatus(200);
    }
}
