package com.acme.admin;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ProxyServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String host = request.getParameter("proxyHost");
        String port = request.getHeader("X-Proxy-Port");
~>        System.setProperty("http.proxyHost", host);
~>        System.setProperty(
            "http.proxyPort", port);
        response.setStatus(204);
    }
}
