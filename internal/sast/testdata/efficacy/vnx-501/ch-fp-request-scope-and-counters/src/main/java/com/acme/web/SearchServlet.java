package com.acme.web;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SearchServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String q = req.getParameter("q");
        req.setAttribute("q", q);
        Integer hits = (Integer) req.getSession().getAttribute("hits");
        req.getSession().setAttribute("hits", hits == null ? 1 : hits + 1);
        req.getSession().setAttribute("lastSearchAt", System.currentTimeMillis());
        req.getRequestDispatcher("/search.jsp").forward(req, resp);
    }
}
