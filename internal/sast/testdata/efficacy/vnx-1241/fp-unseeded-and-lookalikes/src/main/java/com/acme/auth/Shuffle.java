package com.acme.auth;

import java.util.Random;

public class Shuffle {
    // new Random(42) would make the order reproducible.
    private final Random rnd = new Random();
    private final String note = "call new Random(seed) for repeatable tests";

    public int pick(int n) {
        return rnd.nextInt(n);
    }

    public void setSeed(long seed) {
        // a method that happens to be named setSeed
    }

    public RandomGenerator custom(long seed) {
        return new RandomGenerator(seed);
    }

    static class RandomGenerator {
        RandomGenerator(long s) {}
    }
}
