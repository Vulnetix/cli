package com.acme.auth;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LoginServlet extends HttpServlet {
    private static final Logger log = LoggerFactory.getLogger(LoginServlet.class);

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        if (!AuthService.check(username, password)) {
~>            log.warn("Failed login for user " + username);
            response.sendError(401);
            return;
        }
~>        log.info("Login from {} using {}", request.getRemoteAddr(), request.getHeader("User-Agent"));
        response.sendRedirect("/home");
    }
}
