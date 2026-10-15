package com.acme;

public class Registry {
    private static int total;
    private int mine;

    public synchronized void add() {
        mine++;
        synchronized (Registry.class) {
            total++;
        }
    }

    public static synchronized int total() {
        total = Math.max(total, 0);
        return total;
    }
}
