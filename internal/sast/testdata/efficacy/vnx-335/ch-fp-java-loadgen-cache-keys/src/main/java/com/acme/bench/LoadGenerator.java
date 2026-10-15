package com.acme.bench;

import java.util.Random;

public class LoadGenerator {
    private final Random rnd = new Random(42);

    public String nextCacheKey() {
        String key = "user:" + rnd.nextInt(1000);
        return key;
    }

    public int nextPayloadSize() {
        return 128 + rnd.nextInt(4096);
    }
}
