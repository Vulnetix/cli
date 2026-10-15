package com.shop.web;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ProductServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
~>        int id = Integer.parseInt(request.getParameter("id"));
~>        long page = Long.parseLong(request.getParameter("page").trim());
        response.getWriter().println(render(id, page));
    }

    String render(int id, long page) { return id + ":" + page; }
}
