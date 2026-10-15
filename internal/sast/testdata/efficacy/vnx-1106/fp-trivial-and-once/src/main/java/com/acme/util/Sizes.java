package com.acme.util;

public class Sizes {

    public long kib(long b) {
        return b / 1024;
    }

    public long mib(long b) {
        return b / 1024 / 1024;
    }

    public int percent(int part, int whole) {
        return part * 100 / whole;
    }

    public long millis(long s) {
        return s * 1000;
    }

    public int clamp(int v) {
        return Math.min(v, 255) & 0xFF;
    }

    public int port() {
        return 8443;
    }

    public double ratio(double x) {
        return x * 1.125 + 3.14159;
    }

    public int year() {
        return 2024;
    }
}
