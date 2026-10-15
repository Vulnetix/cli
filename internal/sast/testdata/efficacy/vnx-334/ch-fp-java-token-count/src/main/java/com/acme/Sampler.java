package com.acme;

import java.util.Random;

public class Sampler {
    private final Random rnd = new Random();

    public int sampleSize(int bucketCount) {
        int bucket = rnd.nextInt(bucketCount);
        int tokenCount = rnd.nextInt(10);
        return bucket + tokenCount;
    }

    public long session() {
        long sessionKey = new java.security.SecureRandom().nextLong();
        return sessionKey;
    }
}
