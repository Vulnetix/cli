package com.acme.net;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PingServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String host = request.getParameter("host");
        response.setContentType("text/plain");
~>        Process p = Runtime.getRuntime().exec("ping -c 1 " + host);
        response.getWriter().println("started " + p.toString());
    }
}
