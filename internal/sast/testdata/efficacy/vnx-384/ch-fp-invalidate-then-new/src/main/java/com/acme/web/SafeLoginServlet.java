package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class SafeLoginServlet extends HttpServlet {
    private final UserService users = new UserService();

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        User user = users.checkPassword(req.getParameter("user"), req.getParameter("password"));
        if (user == null) {
            resp.sendError(401);
            return;
        }
        HttpSession old = req.getSession(false);
        if (old != null) {
            old.invalidate();
        }
        HttpSession session = req.getSession(true);
        session.setAttribute("user", user);
        resp.sendRedirect("/");
    }

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        HttpSession session = req.getSession();
        session.setAttribute("locale", req.getLocale());
        session.setAttribute("cart", new Cart());
        String msg = "session.setAttribute(\"user\", u) after checking the password";
        resp.getWriter().write(msg);
    }
}
