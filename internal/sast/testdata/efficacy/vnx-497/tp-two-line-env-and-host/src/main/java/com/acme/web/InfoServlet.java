package com.acme.web;

import java.io.IOException;
import java.net.InetAddress;
import java.util.Map;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class InfoServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        Map<String, String> env = System.getenv();
        String host = InetAddress.getLocalHost().getHostName();
        String os = System.getProperty("os.name") + " " + System.getProperty("os.version");
~>        resp.getWriter().printf("env=%s%n", env);
~>        resp.getWriter().append("host=").append(host);
        String banner = "OS " + os;
~>        resp.getOutputStream().write(banner.getBytes());
    }
}
