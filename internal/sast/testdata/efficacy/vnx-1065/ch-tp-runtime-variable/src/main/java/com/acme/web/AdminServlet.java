package com.acme.web;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AdminServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
        Runtime rt = Runtime.getRuntime();
        if ("shutdown".equals(req.getParameter("op"))) {
~>            rt.halt(0);
        }
    }
}
