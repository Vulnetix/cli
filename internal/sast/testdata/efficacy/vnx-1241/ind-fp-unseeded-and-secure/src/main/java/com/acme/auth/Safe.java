package com.acme.auth;

import java.security.SecureRandom;
import java.util.Random;

public class Safe {
    private final Random jitter = new Random();
    private final SecureRandom secure = new SecureRandom();

    public byte[] salt(byte[] extra) {
        secure.setSeed(extra);
        byte[] out = new byte[16];
        secure.nextBytes(out);
        return out;
    }

    public int backoff() {
        return jitter.nextInt(250);
    }
}
