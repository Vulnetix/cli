package com.acme.auth;

import javax.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import @@sample:o[r]g[.][s]lf[4]j[.][L]og[g]er[F]ac[t]or[y]@@;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {
    private static final Logger LOG = LoggerFactory.getLogger(LoginController.class);

    @PostMapping("/login")
    public String login(HttpServletRequest request, @RequestHeader("User-Agent") String agent) {
        String user = request.getParameter("username");
        if (!authenticate(user, request.getParameter("password"))) {
~>            LOG.warn("Login failed for {} from {}", user, agent);
            return "denied";
        }
~>        LOG.info("Forwarded for: " + request.getHeader("X-Forwarded-For"));
        return "ok";
    }
}
