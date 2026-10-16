package com.acme.web;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LoginServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
        String password = req.getParameter("password");
        Cookie saved = new Cookie("password", password);
~>        saved.setMaxAge(14 * 24 * 3600);
        saved.setHttpOnly(true);
        resp.addCookie(saved);
    }
}
