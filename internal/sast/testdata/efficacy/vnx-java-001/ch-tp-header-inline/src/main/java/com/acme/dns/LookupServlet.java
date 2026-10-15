package com.acme.dns;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LookupServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws java.io.IOException {
~>        Process proc = Runtime.getRuntime().exec("nslookup " + req.getHeader("X-Lookup-Host"));
        proc.getInputStream().transferTo(resp.getOutputStream());
    }
}
