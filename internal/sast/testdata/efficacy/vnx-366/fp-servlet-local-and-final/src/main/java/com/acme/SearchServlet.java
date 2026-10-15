package com.acme;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;
import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SearchServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private final AtomicInteger hits = new AtomicInteger();
    private String indexDir;

    @Override
    public void init(ServletConfig cfg) {
        indexDir = cfg.getInitParameter("indexDir");
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String q = req.getParameter("q");
        int count = 0;
        count++;
        hits.incrementAndGet();
        resp.getWriter().write(q + indexDir + count);
    }
}
