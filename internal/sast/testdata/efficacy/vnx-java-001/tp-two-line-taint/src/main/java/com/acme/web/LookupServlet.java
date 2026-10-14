package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LookupServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String cmd = "nslookup " + req.getParameter("name");
~>        Process p = Runtime.getRuntime().exec(cmd);

        String target = req.getHeader("X-Target");
~>        Runtime.getRuntime().exec(target);

        String user = req.getParameter("user");
        String line = "id " + user;
~>        Runtime.getRuntime().exec(line);
    }
}
