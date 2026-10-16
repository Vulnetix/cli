package com.acme.web;

import javax.servlet.http.*;

public class LoginServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
        Account acct = accounts.authenticate(req.getParameter("u"), req.getParameter("p"));
~>        Cookie levelCookie = new Cookie("access_level", String.valueOf(acct.getLevel()));
        levelCookie.setHttpOnly(true);
        resp.addCookie(levelCookie);
    }
}
