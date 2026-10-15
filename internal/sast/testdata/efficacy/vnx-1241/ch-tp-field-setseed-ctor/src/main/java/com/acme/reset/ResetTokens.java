package com.acme.reset;

import java.util.Random;

public class ResetTokens {
    private Random rng;

    public ResetTokens() {
        this.rng = new Random();
    }

    public String tokenFor(String email) {
~>        this.rng.setSeed(email.hashCode());
        return Long.toHexString(rng.nextLong());
    }
}
