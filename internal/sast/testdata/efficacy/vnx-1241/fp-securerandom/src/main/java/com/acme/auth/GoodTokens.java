package com.acme.auth;

import java.security.SecureRandom;
import java.util.Random;

public class GoodTokens {
    private final SecureRandom secure = new SecureRandom();
    private final Random strong = SecureRandom.getInstanceStrong();

    public GoodTokens() throws Exception {
    }

    public void mix(byte[] extra) {
        secure.setSeed(extra);
    }

    public long next() {
        return secure.nextLong();
    }
}
