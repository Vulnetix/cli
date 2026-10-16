package com.acme.cache;

import java.util.Random;

public class SafeRouter {
    private final Random r = new Random();

    public int route(String key, int n) {
        return Math.floorMod(key.hashCode(), n);
    }

    public int masked(String key, int n) {
        return (key.hashCode() & 0x7fffffff) % n;
    }

    public int pick(int n) {
        return Math.abs(r.nextInt(n));
    }

    public int scaled(int total, int parts) {
        return total / parts;
    }
}
