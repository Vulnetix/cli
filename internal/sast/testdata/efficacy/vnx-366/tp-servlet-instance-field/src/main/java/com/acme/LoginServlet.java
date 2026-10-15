package com.acme;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LoginServlet extends HttpServlet {
    private String currentUser;
    private int attempts = 0;

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
~>        currentUser = req.getParameter("user");
~>        this.attempts++;
        resp.getWriter().write("hello " + currentUser);
    }

    @Override
    public void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {
        String name = req.getParameter("name");
~>        this.currentUser = name;
        resp.getWriter().write(currentUser);
    }
}
