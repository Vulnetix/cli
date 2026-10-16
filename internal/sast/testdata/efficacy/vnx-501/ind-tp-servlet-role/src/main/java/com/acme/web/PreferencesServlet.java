package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class PreferencesServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String role = req.getParameter("role");
~>        req.getSession().setAttribute("role", role);

        String tenant = req.getHeader("X-Tenant-Id");
        String normalized = tenant.trim();
        HttpSession session = req.getSession(true);
~>        session.setAttribute("tenant", normalized);
        resp.sendRedirect("/home");
    }
}
