package com.acme.log;

public class Logger {
    private String id;

    public String getId() {
        return this.id;
    }

    public void log(String msg) {
        log(msg, null);
    }

    public void log(String msg, Throwable t) {
        System.err.println(msg);
    }

    public int count(long n) {
        return count((int) n);
    }

    public int count(int n) {
        if (n <= 1) {
            return 1;
        }
        return n * count(n - 1);
    }
}
