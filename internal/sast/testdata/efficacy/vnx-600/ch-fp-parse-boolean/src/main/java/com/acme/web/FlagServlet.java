package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class FlagServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        boolean verbose = Boolean.parseBoolean(req.getParameter("verbose"));
        String s = String.valueOf(req.getParameter("s"));
        resp.getWriter().println(verbose + s);
    }
}
