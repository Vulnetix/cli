package com.acme.web;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AdminServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
~>        if ("true".equals(request.getParameter("isAdmin"))) {
            showAdmin(response);
            return;
        }
        for (Cookie c : request.getCookies()) {
~>            if (c.getName().equals("role") && c.getValue().equals("admin")) {
                showAdmin(response);
                return;
            }
        }
        String role = request.getHeader("X-Role");
~>        if (role != null && role.equalsIgnoreCase("admin")) {
            showAdmin(response);
        }
    }

    private void showAdmin(HttpServletResponse response) {}
}
