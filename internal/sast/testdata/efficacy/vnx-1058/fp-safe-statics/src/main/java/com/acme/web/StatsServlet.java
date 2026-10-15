package com.acme.web;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class StatsServlet extends HttpServlet {
    private static final Map<String, String> LABELS = new HashMap<>();
    private static AtomicInteger hits = new AtomicInteger();
    private static ConcurrentHashMap<String, Integer> perUser = new ConcurrentHashMap<>();
    private static volatile boolean enabled = true;
    private static Map<String, Long> seen = Collections.synchronizedMap(new HashMap<>());
    private static Map<String, String> questions;
    private static String banner = "stats";
    private static int total;

    static {
        questions = new HashMap<>();
        questions.put("colour", "blue");
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        hits.incrementAndGet();
        perUser.merge(req.getRemoteUser(), 1, Integer::sum);
        enabled = req.getParameter("off") == null;
        resp.setHeader("X-Banner", banner + questions.get("colour"));
        synchronized (StatsServlet.class) {
            total++;
        }
    }
}
