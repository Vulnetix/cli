package com.acme.web;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LoginServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
        Account acct = accounts.login(req.getParameter("user"), req.getParameter("pass"));
~>        Cookie roleCookie = new Cookie("role", acct.getRole());
        roleCookie.setHttpOnly(true);
        resp.addCookie(roleCookie);
        resp.addCookie(new Cookie("lang", acct.getLocale()));
    }

    static boolean isAdmin(HttpServletRequest req) {
        for (Cookie c : req.getCookies()) {
~>            if (c.getName().equals("isAdmin") && "true".equals(c.getValue())) {
                return true;
            }
~>            if ("userRole".equalsIgnoreCase(c.getName())) {
                return "admin".equals(c.getValue());
            }
        }
        return false;
    }
}
