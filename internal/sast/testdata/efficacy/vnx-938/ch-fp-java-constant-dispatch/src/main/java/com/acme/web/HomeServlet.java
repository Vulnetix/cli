package com.acme.web;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

public class HomeServlet extends HttpServlet {
    private static final Map<String, String> VIEWS = Map.of("home", "/WEB-INF/home.jsp", "about", "/WEB-INF/about.jsp");

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String name = req.getParameter("view");
        req.setAttribute("name", name);
        req.getRequestDispatcher("/WEB-INF/home.jsp").forward(req, resp);
    }
}
