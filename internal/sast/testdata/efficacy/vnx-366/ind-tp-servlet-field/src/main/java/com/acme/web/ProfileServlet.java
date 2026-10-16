package com.acme.web;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ProfileServlet extends HttpServlet {
    private String username;
    private int views;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
~>        username = req.getParameter("user");
~>        views++;
        resp.getWriter().printf("Hello %s, view %d%n", username, views);
    }
}
