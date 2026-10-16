package com.acme.web;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AboutServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/plain");
        response.getWriter().println("Acme Portal 4.2");
~>        response.getWriter().println("Java: " + System.getProperty("java.version"));
~>        response.getWriter().printf("OS: %s %s%n", System.getProperty("os.name"), System.getProperty("os.version"));
    }
}
