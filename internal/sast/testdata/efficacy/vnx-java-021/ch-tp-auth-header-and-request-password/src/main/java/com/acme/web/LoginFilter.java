package com.acme.web;

import javax.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import @@sample:o[r]g[.][s]lf[4]j[.][L]og[g]er[F]ac[t]or[y]@@;

public class LoginFilter {
    private static final Logger logger = LoggerFactory.getLogger(LoginFilter.class);

    public void inspect(HttpServletRequest request) {
~>        logger.debug("login form: user={} pass={}", @@sample:r[e]qu[e]st[.]ge[t]Pa[r]am[e]te[r]@@("username"), @@sample:r[e]qu[e]st[.]ge[t]Pa[r]am[e]te[r]@@("password"));
        logger.info("Login request for {}", request.getParameter("username"));
    }
}
