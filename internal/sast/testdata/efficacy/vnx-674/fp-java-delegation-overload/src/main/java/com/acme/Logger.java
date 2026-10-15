package com.acme;

public class Logger {
    private String id;

    public String getId() {
        return this.id;
    }

    public void log(String msg) {
        log(msg, null);
    }

    public int count(long n) {
        return count((int) n);
    }

    public String getName() {
        return delegate.getName();
    }
}
