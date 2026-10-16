package com.acme.web;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;
import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SafeServlet extends HttpServlet {
    private static final AtomicInteger hits = new AtomicInteger();
    private String greeting;

    @Override
    public void init(ServletConfig config) {
        greeting = config.getInitParameter("greeting");
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String user = req.getParameter("user");
        int n = hits.incrementAndGet();
        for (int i = 0; i < 1; i++) {
            user = user.trim();
        }
        resp.getWriter().printf("%s %s #%d%n", greeting, user, n);
    }
}
