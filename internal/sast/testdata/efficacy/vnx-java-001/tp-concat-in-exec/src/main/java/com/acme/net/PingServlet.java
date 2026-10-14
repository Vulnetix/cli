package com.acme.net;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PingServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String host = request.getParameter("host");
~>        Process p = Runtime.getRuntime().exec("ping -c 1 " + host);
~>        Process q = Runtime.getRuntime().exec("whois "+request.getParameter("domain"));
~>        Runtime.getRuntime().exec(String.format("traceroute %s", host));
        response.getWriter().println(p.waitFor() + q.waitFor());
    }
}
