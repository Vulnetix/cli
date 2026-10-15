package com.shop.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class StatusServlet extends HttpServlet {
    private static final String DEFAULT_LIMIT = "50";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // int id = Integer.parseInt(request.getParameter("id"));
        int limit = Integer.parseInt(DEFAULT_LIMIT);
        String name = request.getParameter("name");
        response.getWriter().println("Integer.parseInt(request.getParameter(\"x\")) " + limit + name);
    }
}
