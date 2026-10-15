package com.acme;

public class Counter {
    private static final Object LOCK = new Object();
    private static int created;
    private final StringBuilder log = new StringBuilder();
    private int value;

    public Counter() {
        synchronized (LOCK) {
            created++;
        }
    }

    public void record(String msg) {
        synchronized (log) {
            log.append(msg);
        }
    }

    public void bump() {
        Object newObjectFactory = null;
        synchronized (Counter.this) {
            value++;
        }
    }

    public static int created() {
        synchronized (Counter.class) {
            return created;
        }
    }
}
