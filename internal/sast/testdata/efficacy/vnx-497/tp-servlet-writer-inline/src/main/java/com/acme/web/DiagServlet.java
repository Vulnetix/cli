package com.acme.web;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class DiagServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
~>        response.getWriter().println("Java: " + System.getProperty("java.version"));
        PrintWriter out = response.getWriter();
~>        out.println("Running from " + System.getProperty("user.dir"));
~>        out.write(System.getProperties().toString());
    }
}
