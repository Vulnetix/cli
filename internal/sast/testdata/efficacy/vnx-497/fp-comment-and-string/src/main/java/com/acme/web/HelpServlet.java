package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class HelpServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // do not write response.getWriter().println(System.getProperty("user.dir"))
        response.getWriter().println("Never print System.getProperty(\"user.home\") to clients");
    }
}
