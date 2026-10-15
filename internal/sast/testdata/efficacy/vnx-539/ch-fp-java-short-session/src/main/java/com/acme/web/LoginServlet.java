package com.acme.web;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

public class LoginServlet {
    void issue(HttpServletResponse resp, String token) {
        Cookie auth = new Cookie("auth_token", token);
        auth.setHttpOnly(true);
        auth.setMaxAge(30 * 60);
        resp.addCookie(auth);
    }

    void logout(HttpServletResponse resp) {
        Cookie gone = new Cookie("auth_token", "");
        gone.setMaxAge(0);
        resp.addCookie(gone);
    }
}
