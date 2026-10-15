package com.acme;

public class Worker implements Runnable {
    private static final String NAME = "worker";
    private long processed;
    private static String describe(int n) {
        String label = NAME + n;
        return label;
    }

    @Override
    public void run() {
        processed++;
    }
}
