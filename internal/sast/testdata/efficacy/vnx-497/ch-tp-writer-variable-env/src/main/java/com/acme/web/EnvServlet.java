package com.acme.web;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Map;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class EnvServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        PrintWriter out = resp.getWriter();
        Map<String, String> env = System.getenv();
        for (Map.Entry<String, String> e : env.entrySet()) {
~>            out.println(e.getKey() + "=" + env.get(e.getKey()));
        }
~>        resp.getWriter().write("tmp=" + System.getProperty("java.io.tmpdir"));
    }
}
