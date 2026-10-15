package com.acme.web;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SafeServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        if (request.isUserInRole("admin")) {
            show(response);
        }
        Object role = request.getSession().getAttribute("role");
        if ("admin".equals(role)) {
            show(response);
        }
        String lang = request.getParameter("lang");
        if ("en".equals(lang)) {
            show(response);
        }
    }

    private void show(HttpServletResponse response) {}
}
