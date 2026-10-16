package com.acme;

import java.util.Random;

public class Safe {
    private final Random r = new Random();

    int a(String key, int n) {
        return Math.floorMod(key.hashCode(), n);
    }

    int b(String key, int n) {
        return (key.hashCode() & 0x7fffffff) % n;
    }

    int c(int n) {
        return Math.abs(r.nextInt(n));
    }

    double d(double x) {
        return x / 0.0;
    }

    int e(int x, int y) {
        return x / 0x10 + x % 7 + x / y;
    }
}
