package com.example;

import java.util.Random;

public class Safe {
    public int shard(String key, int n, Random r) {
        int a = Math.floorMod(key.hashCode(), n);
        int b = (key.hashCode() & 0x7fffffff) % n;
        int c = r.nextInt(n);
        int d = Math.abs(r.nextInt(100));
        int e = Math.abs(a - b);
        return a + b + c + d + e;
    }
}
