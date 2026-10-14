package com.acme.auth;

import java.util.Random;

public class TokenService {
    private static final Random RANDOM = new Random();
    private final Random rnd = new Random(System.currentTimeMillis());

    public String newSessionId() {
~>        return Long.toHexString(RANDOM.nextLong()) + Long.toHexString(RANDOM.nextLong());
    }

    public byte[] apiKey() {
        byte[] apiKey = new byte[32];
~>        rnd.nextBytes(apiKey);
        return apiKey;
    }

    public String issue() {
~>        String token = Integer.toString(rnd.nextInt(1_000_000));
        return token;
    }
}
