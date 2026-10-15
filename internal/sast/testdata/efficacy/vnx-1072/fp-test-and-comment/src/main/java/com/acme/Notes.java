package com.acme;

public class Notes {
    // Never call DriverManager.getConnection(url) per request; use the pool.
    static final String HINT = "DriverManager.getConnection(url) bypasses the pool";
}
