package com.shop.auth;

import java.util.Random;

public class ResetTokens {
    private final Random rnd = new Random();

    public String createResetToken() {
~>        rnd.setSeed(System.currentTimeMillis() % 1000);
        return Long.toHexString(rnd.nextLong());
    }
}
