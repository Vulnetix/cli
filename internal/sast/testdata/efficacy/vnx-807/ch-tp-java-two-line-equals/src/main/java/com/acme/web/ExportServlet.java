package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ExportServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String accountType = req.getHeader("X-Account-Type");
~>        if ("administrator".equalsIgnoreCase(accountType)) {
            resp.getWriter().write("full export");
            return;
        }
        resp.sendError(403);
    }
}
