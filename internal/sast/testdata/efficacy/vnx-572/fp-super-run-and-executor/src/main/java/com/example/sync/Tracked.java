package com.example.sync;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Tracked extends Thread {
    private final Runnable inner;

    public Tracked(Runnable inner) {
        super(inner);
        this.inner = inner;
    }

    @Override
    public void run() {
        long t0 = System.nanoTime();
        super.run();
        inner.run();
        System.out.println(System.nanoTime() - t0);
    }

    public static void submit(Runnable job) {
        ExecutorService pool = Executors.newFixedThreadPool(2);
        pool.submit(job);
        Thread t = new Thread(job);
        t.start();
        t.join();
    }
}
