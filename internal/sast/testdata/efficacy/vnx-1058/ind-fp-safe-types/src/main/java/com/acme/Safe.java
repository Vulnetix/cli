package com.acme;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import javax.servlet.http.*;

public class Safe extends HttpServlet {
    private static final Map<String, String> CONST = new HashMap<>();
    private static AtomicInteger hits = new AtomicInteger();
    private static volatile boolean ready;
    private static ConcurrentHashMap<String, Integer> m = new ConcurrentHashMap<>();
    private static final ThreadLocal<java.text.SimpleDateFormat> DF =
        ThreadLocal.withInitial(() -> new java.text.SimpleDateFormat("yyyy"));
    private static Map<String, String> sync = Collections.synchronizedMap(new HashMap<>());
    private static int count;
    private static List<String> names = new ArrayList<>();

    static { names.add("a"); count = 1; }

    public static synchronized void increment() { count++; }

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        hits.incrementAndGet();
        m.put("k", 1);
        ready = true;
        sync.put("a", "b");
    }
}
