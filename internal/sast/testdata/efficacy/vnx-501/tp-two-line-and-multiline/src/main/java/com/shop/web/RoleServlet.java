package com.shop.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class RoleServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String role = req.getParameter("role");
        String tenant = req.getQueryString();
~>        req.getSession().setAttribute("role", role);
~>        req.getSession().setAttribute(
                "tenant",
                tenant);
        resp.getWriter().println("ok");
    }
}
