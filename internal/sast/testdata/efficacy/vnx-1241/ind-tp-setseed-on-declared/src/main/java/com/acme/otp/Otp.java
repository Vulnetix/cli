package com.acme.otp;

import java.util.Random;

public class Otp {
    private final Random random = new Random();

    public int code(String key) {
~>        random.setSeed(key.length());
        return random.nextInt(1_000_000);
    }
}
