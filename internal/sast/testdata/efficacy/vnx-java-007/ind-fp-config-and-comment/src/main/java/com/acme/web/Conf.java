package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServletResponse;

public class Conf {
    private final String loginUrl;

    Conf(String loginUrl) { this.loginUrl = loginUrl; }

    void go(HttpServletResponse resp) throws IOException {
        // resp.sendRedirect(request.getParameter("next"));
        resp.sendRedirect(loginUrl);
    }
}
