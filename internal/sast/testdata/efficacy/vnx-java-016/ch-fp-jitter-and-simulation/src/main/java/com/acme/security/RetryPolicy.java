package com.acme.security;

import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

public class RetryPolicy {
    private final Random random = new Random();
    private final long base = 200;

    public long nextDelay(int attempt) {
        long delay = base * (1L << attempt) + random.nextInt(250);
        return delay;
    }

    public double noise(long seed) {
        Random rnd = new Random(seed);
        return rnd.nextGaussian();
    }

    public String pickColor(String[] palette) {
        String cacheKey = "color-" + ThreadLocalRandom.current().nextInt(palette.length);
        return cacheKey;
    }
}
