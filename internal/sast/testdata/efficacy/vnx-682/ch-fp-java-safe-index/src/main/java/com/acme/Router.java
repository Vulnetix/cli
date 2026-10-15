package com.acme;

import java.util.Random;

public class Router {
    int route(String key, int n, Random rnd) {
        int a = Math.floorMod(key.hashCode(), n);
        int b = Math.abs(rnd.nextInt(100));
        int c = (key.hashCode() & 0x7fffffff) % n;
        return a + b + c;
    }
}
