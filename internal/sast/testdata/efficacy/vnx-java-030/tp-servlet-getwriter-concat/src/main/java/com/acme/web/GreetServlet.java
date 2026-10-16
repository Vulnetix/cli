package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class GreetServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html;charset=UTF-8");
        String name = request.getParameter("name");
~>        response.getWriter().println("<p>Hello " + name + "</p>");
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
~>        response.getWriter().write("<h1>" + request.getParameter("title") + "</h1>");
    }

    protected void search(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.setContentType("text/html");
        String q = req.getQueryString();
        String shown = q == null ? "" : q;
~>        resp.getWriter().append("You searched for ").append(shown);
        resp.getWriter().println("<hr>");
    }
}
