package com.acme;

import java.security.SecureRandom;

public class NonceSource {
    private final SecureRandom sr = new SecureRandom();

    public NonceSource() {
~>        sr.setSeed(System.currentTimeMillis());
    }

    public byte[] next(int len) {
        byte[] out = new byte[len];
        sr.nextBytes(out);
        return out;
    }
}
