package com.acme.web;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class LoginServlet extends HttpServlet {
    private AccountService accounts;

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String email = request.getParameter("email");
        String password = request.getParameter("password");
        Account account = accounts.authenticate(email, password);
        if (account == null) {
            response.sendRedirect("/login?error=1");
            return;
        }
        HttpSession session = request.getSession(true);
~>        session.setAttribute("userId", account.getId());
~>        session.setAttribute("role", account.getRole());
        response.sendRedirect("/dashboard");
    }
}
