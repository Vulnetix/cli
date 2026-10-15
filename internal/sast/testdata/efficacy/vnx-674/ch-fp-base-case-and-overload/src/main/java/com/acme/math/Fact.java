package com.acme.math;

public class Fact {
    public long fact(int n) {
        if (n <= 1) return 1;
        return n * fact(n - 1);
    }

    public void log(String msg) {
        log(msg, Level.INFO);
    }

    public String getName() { return name; }

    public void close() {
        Outer.this.close();
    }
}
