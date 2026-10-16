package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class RegisterServlet extends HttpServlet {
    private final UserDao users = new UserDao();

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String username = request.getParameter("username");
        String pw = request.getParameter("password");
        Account account = new Account();
        account.setUsername(username);
~>        account.setPassword(pw);
        users.save(account);
        response.sendRedirect("/login");
    }
}
