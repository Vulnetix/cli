package com.acme.web;

import javax.annotation.Resource;
import javax.enterprise.concurrent.ManagedExecutorService;
import javax.servlet.http.HttpServlet;

public class JobServlet extends HttpServlet {
    @Resource
    private ManagedExecutorService executor;

    // never call System.exit(0) from a servlet
    private static final String NOTE = "do not use new Thread( here";

    void submit(Runnable r) {
        executor.submit(r);
        Thread.currentThread().interrupt();
    }
}
