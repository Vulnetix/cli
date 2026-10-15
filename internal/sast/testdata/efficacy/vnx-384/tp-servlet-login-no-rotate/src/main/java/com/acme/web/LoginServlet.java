package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class LoginServlet extends HttpServlet {
    private final UserStore users = new UserStore();

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("username");
        String password = request.getParameter("password");
        User user = users.authenticate(name, password);
        if (user == null) {
            response.sendError(401);
            return;
        }
        HttpSession session = request.getSession();
~>        session.setAttribute("user", user);
~>        session.setAttribute("userId", user.getId());
        response.sendRedirect("/home");
    }
}

class ApiLogin {
    static final String SESSION_USER = "user";
    static final String AUTHENTICATION_CHALLENGE = "challenge";

    public void login(javax.servlet.http.HttpServletRequest request, String password, User user) {
        javax.servlet.http.HttpSession s = request.getSession();
        s.setAttribute(AUTHENTICATION_CHALLENGE, newChallenge());
        if (user.checkPassword(password)) {
~>            s.setAttribute(SESSION_USER, user);
        }
    }
}
