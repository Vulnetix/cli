package com.acme;

import java.security.SecureRandom;

public class Keys {
    private final SecureRandom rng = new SecureRandom();

    public byte[] key() throws Exception {
        SecureRandom strong = SecureRandom.getInstanceStrong();
        byte[] k = new byte[32];
        strong.nextBytes(k);
        rng.setSeed(strong.generateSeed(32));
        return k;
    }
}
