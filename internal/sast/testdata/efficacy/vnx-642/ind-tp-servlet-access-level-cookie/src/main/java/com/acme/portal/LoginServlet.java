package com.acme.portal;

import java.io.IOException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LoginServlet extends HttpServlet {
    private final AccountService accounts = new AccountService();

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        Account acct = accounts.authenticate(req.getParameter("user"), req.getParameter("pass"));
        if (acct == null) {
            resp.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }
        req.getSession(true).setAttribute("accountId", acct.getId());
~>        Cookie level = new Cookie("access_level", String.valueOf(acct.getAccessLevel()));
        level.setPath("/");
        level.setHttpOnly(true);
        resp.addCookie(level);
        resp.sendRedirect("/dashboard");
    }
}
