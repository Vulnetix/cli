package com.acme;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class StatsServlet extends HttpServlet {
    private int hits;
    private final AtomicInteger views = new AtomicInteger();
    private final Map<String, Integer> byPath = new ConcurrentHashMap<>();
    private volatile boolean warmed;
    private long bytes;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        synchronized (this) {
            hits++;
        }
        views.incrementAndGet();
        byPath.merge(req.getRequestURI(), 1, Integer::sum);
        warmed = true;
        addBytes(10);
    }

    private synchronized void addBytes(long n) {
        bytes += n;
    }
}
