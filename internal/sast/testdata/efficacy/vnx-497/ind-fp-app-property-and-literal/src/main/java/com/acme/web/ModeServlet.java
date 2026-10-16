package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ModeServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Never write System.getProperty("java.version") to the client here.
        String mode = System.getProperty("acme.mode", "standard");
        response.getWriter().println("mode=" + mode);
        response.getWriter().println("Tip: run with -Dacme.mode=debug, not System.getProperty(\"os.name\")");
    }
}
