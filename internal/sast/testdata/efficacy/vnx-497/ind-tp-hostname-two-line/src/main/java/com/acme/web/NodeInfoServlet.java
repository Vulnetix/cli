package com.acme.web;

import java.io.IOException;
import java.net.InetAddress;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class NodeInfoServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String host = InetAddress.getLocalHost().getHostName();
        resp.setContentType("text/plain");
~>        resp.getWriter().append("served-by=").append(host);
    }
}
