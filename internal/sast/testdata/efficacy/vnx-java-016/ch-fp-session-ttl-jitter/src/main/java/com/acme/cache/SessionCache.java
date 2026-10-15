package com.acme.cache;

import java.util.Random;

public class SessionCache {
    private static final long BASE_TTL = 3600;
    private final Random random = new Random();

    public long sessionTtlSeconds() {
        long sessionTtl = BASE_TTL + random.nextInt(600);
        return sessionTtl;
    }

    public long refreshAfter() {
        long tokenExpirySeconds = BASE_TTL + random.nextInt(60);
        return tokenExpirySeconds;
    }

    public int tokenBucketRefillJitterMs() {
        return random.nextInt(25);
    }
}
