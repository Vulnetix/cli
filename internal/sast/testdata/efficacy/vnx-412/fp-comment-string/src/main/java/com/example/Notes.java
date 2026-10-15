package com.example;

public class Notes {
    // synchronized ("refresh") locks a JVM-wide interned string
    /* public final Object lock = new Object(); exposes the monitor */
    static final String HINT = "never write synchronized (name.intern())";
}
