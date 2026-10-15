package com.acme.web;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.annotation.WebListener;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@WebListener
public class StartupListener implements ServletContextListener {
    private ExecutorService pool;

    @Override
    public void contextInitialized(ServletContextEvent sce) {
~>        pool = Executors.newFixedThreadPool(4);
~>        Thread warm = new Thread(() -> warmCaches(), "warm-caches");
        warm.start();
    }
}
