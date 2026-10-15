package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PageServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        int page;
        try
        {
            page = Integer.parseInt(req.getParameter("page"));
        }
        catch (NumberFormatException e)
        {
            resp.sendError(400);
            return;
        }
        resp.getWriter().println(page);
    }
}
