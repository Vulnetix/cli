package com.acme.auth;

import java.util.Random;

public class ResetTokens {
~>    private final Random rng = new Random(42L);

    public String next() {
        return Long.toHexString(rng.nextLong());
    }
}
