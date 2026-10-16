package com.acme.web;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LogoutServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        Cookie gone = new Cookie("auth_token", "");
        gone.setMaxAge(0);
        gone.setPath("/");
        resp.addCookie(gone);
    }
}
