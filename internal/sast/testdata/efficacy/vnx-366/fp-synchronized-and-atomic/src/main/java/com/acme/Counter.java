package com.acme;

import java.util.concurrent.atomic.AtomicLong;

public class Counter implements Runnable {
    private static int done;
    private static volatile boolean stop;
    private static final AtomicLong total = new AtomicLong();
    private static final Object LOCK = new Object();
    private static int other;

    @Override
    public void run() {
        total.addAndGet(5);
        synchronized (LOCK) {
            done++;
        }
        bump();
        stop = true;
    }

    private static synchronized void bump() {
        other++;
    }

    public static void main(String[] args) {
        new Thread(new Counter()).start();
    }
}
