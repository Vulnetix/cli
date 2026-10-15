package com.acme.otp;

import java.security.SecureRandom;
import java.util.Random;

public class SecureIssuer {
    private final Random random = new SecureRandom();
    private final SecureRandom strong = SecureRandom.getInstanceStrong();

    public SecureIssuer(byte[] extraEntropy) {
        strong.setSeed(extraEntropy);
    }

    public String issue() {
        Random local = new Random();
        return String.format("%06d", random.nextInt(1_000_000)) + local.nextInt(9);
    }
}
