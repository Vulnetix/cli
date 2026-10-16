package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ApiServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("application/json");
        String id = request.getParameter("id");
        response.getWriter().write("{\"id\": \"" + id + "\"}");
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/plain;charset=UTF-8");
        response.getWriter().println("echo: " + request.getParameter("msg"));
    }

    protected void doPut(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setHeader("Content-Type", "text/csv");
        response.getWriter().print(request.getParameter("row"));
    }
}
