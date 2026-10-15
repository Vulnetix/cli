package com.acme.auth;

import java.util.Random;

public class Tokens {
    private static final long SEED = 20240101L;
    private Random shared;

    public Tokens(long userId) {
~>        this.shared = new Random(SEED + userId);
    }

    public void reseed() {
        long now = System.currentTimeMillis();
~>        shared.setSeed(now);
    }
}
