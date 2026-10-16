package com.acme;

public class Paren {
    int pct(long done, long total) {
        return (int) (done * 100 / total);
    }
    int small(long n) {
        long limit = 1000;
        return (int) Math.min(n, limit);
    }
}
