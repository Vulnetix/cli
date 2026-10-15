package com.acme;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class HitServlet extends HttpServlet {
    private int hits;
    private String lastUser;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
~>        hits++;
~>        lastUser = req.getParameter("user");
        resp.getWriter().println("Hello " + lastUser + " #" + hits);
    }
}
