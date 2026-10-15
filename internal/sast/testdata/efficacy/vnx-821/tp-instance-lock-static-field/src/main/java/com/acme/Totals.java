package com.acme;

public class Totals {
    private static int total;

    public synchronized void add(int n) {
~>        total += n;
    }

    public static synchronized int get() {
        return total;
    }
}
