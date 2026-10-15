package com.example;

public class Constants {
    public static final String NAME = "service";
    public final Object payload = new Object();
    private final Object guard = new Object();

    public void run() {
        synchronized (guard) {
            System.out.println(NAME + payload);
        }
    }

    public LockStatus getLockStatus() {
        return LockStatus.FREE;
    }
}
