package com.acme;

import java.security.SecureRandom;

public class Rng {
    public byte[] token() {
        SecureRandom sr = new SecureRandom();
        sr.setSeed(sr.generateSeed(32));
        byte[] token = new byte[32];
        sr.nextBytes(token);
        return token;
    }

    public byte[] strongToken() throws Exception {
        SecureRandom strong = SecureRandom.getInstanceStrong();
        byte[] token = new byte[32];
        strong.nextBytes(token);
        return token;
    }
}
