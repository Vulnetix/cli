package com.shop.auth;

import java.util.Random;

public class ApiTokens {
    private static final long SEED = 0xDEADBEEFL;
~>    private final Random rng = new Random(SEED);

    public String generateApiToken() {
        long apiToken = rng.nextLong();
        return Long.toHexString(apiToken);
    }
}
