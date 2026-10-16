package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.RequestParam;

public class CountServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        int page = Integer.parseInt(request.getParameter("page"));
        response.getWriter().println("<p>Page " + page + "</p>");
        boolean full = Boolean.parseBoolean(request.getParameter("full"));
        response.getWriter().println("<p>Full: " + full + "</p>");
        long id = Long.parseLong(request.getHeader("X-Id"));
        response.getWriter().print(id);
    }

    void show(@RequestParam int limit, @RequestParam("on") boolean on, javax.servlet.http.HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        response.getWriter().println("<p>" + limit + on + "</p>");
    }
}
