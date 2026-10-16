package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AverageServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        int sum = Integer.parseInt(req.getParameter("sum"));
        int count = Integer.parseInt(req.getParameter("count"));
~>        int avg = sum / count;
        resp.getWriter().println(avg);
    }
}
