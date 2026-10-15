package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import @@sample:o[r]g[.][s]lf[4]j[.][L]og[g]er[F]ac[t]or[y]@@;

public class LoginServlet extends HttpServlet {
    private static final Logger log = LoggerFactory.getLogger(LoginServlet.class);

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String user = request.getParameter("user");
~>        log.warn("Failed login for user " + user);
~>        log.info("User-Agent: {}", request.getHeader("User-Agent"));
        String ref = request.getHeader("Referer");
        String msg = "referer=" + ref;
~>        LOGGER.error(
            msg);
    }

    private static final java.util.logging.Logger LOGGER = java.util.logging.Logger.getLogger("web");
}
