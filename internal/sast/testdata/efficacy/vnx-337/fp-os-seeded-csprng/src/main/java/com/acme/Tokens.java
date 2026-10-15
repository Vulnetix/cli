package com.acme;

import java.security.SecureRandom;

public class Tokens {
    private final SecureRandom sr = new SecureRandom();

    public byte[] token() {
        long started = System.currentTimeMillis();
        byte[] token = new byte[32];
        sr.nextBytes(token);
        audit(System.currentTimeMillis() - started);
        return token;
    }
}
