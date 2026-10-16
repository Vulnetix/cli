package com.acme.batch;

public class Counter implements Runnable {
    private static int done = 0;
    private static volatile int seen = 0;
    private static final Object LOCK = new Object();

    @Override
    public void run() {
        synchronized (LOCK) {
            done++;
        }
        bump();
    }

    private static synchronized void bump() {
        done += 1;
    }

    public static void main(String[] args) {
        new Thread(new Counter()).start();
    }
}
