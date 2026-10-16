package com.acme;

public class Util {
    private static final long serialVersionUID = 123456789L;
    static final int[] PRIMES = {101, 103, 107};
    static final int[] PRIMES2 = {101, 103, 107};

    int a(int v) { return v & 0xFF; }
    int b(int v) { return v % 1024; }
    int c(int v) { return v * 1000; }
    int d(int v) { return v & 255; }
    int e(int v) { return v & 0xFFFF; }
    // retry after 15000 ms, 15000 ms, 15000 ms
    String s = "15000 15000 15000";
}
