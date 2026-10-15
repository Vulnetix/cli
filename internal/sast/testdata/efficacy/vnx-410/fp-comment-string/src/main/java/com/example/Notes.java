package com.example;

public class Notes {
    // config.setMaximumPoolSize(1) starves the request threads
    /* Executors.newFixedThreadPool(1) behind a ServerSocket serialises clients */
    static final String HINT = "do not call setMaxThreads(1) on the connector";
}
