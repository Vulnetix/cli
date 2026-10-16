package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class SafeLoginServlet extends HttpServlet {
    private AccountService accounts;

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String password = request.getParameter("password");
        Account account = accounts.authenticate(request.getParameter("email"), password);
        if (account == null) {
            response.sendError(401);
            return;
        }
        request.changeSessionId();
        HttpSession session = request.getSession();
        session.setAttribute("userId", account.getId());
        response.sendRedirect("/dashboard");
    }

    protected void legacyLogin(HttpServletRequest request, String user, String password) {
        if (!accounts.checkPassword(user, password)) {
            return;
        }
        HttpSession old = request.getSession(false);
        if (old != null) {
            old.invalidate();
        }
        HttpSession fresh = request.getSession(true);
        fresh.setAttribute("user", user);
    }
}
