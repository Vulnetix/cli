package com.acme;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Loader {
    private static int threads;

    public static void main(String[] args) {
        threads = Integer.parseInt(args[0]);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        pool.shutdown();
    }
}
