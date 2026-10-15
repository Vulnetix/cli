package com.acme;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

class ConcurrencyTest {
    void hammer() {
        ExecutorService pool = Executors.newFixedThreadPool(8);
        pool.submit(() -> System.out.println("hi"));
    }
}
