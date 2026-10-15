package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ItemServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String id = req.getParameter("id");
        if (id == null || !id.matches("\\d{1,9}")) {
            resp.sendError(400);
            return;
        }
        int n = Integer.parseInt(id);
        resp.getWriter().println(n);
    }
}
