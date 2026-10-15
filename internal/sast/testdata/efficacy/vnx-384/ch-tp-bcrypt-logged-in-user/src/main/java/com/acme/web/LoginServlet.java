package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.mindrot.jbcrypt.BCrypt;

public class LoginServlet extends HttpServlet {
    private final AccountRepository accounts = new AccountRepository();

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("username");
        String pw = req.getParameter("password");
        Account account = accounts.findByName(name);
        HttpSession session = req.getSession(true);
        if (account != null && BCrypt.checkpw(pw, account.getHash())) {
~>            session.setAttribute("currentUser", account);
~>            req.getSession().setAttribute(SessionKeys.USER_ID, account.getId());
            resp.sendRedirect("/home");
            return;
        }
        resp.sendRedirect("/login?error");
    }
}
