package com.acme.auth;

import java.util.Random;

public class ResetCodes {
~>    private final Random rng = new Random(42L);

    public String next() {
        return String.format("%06d", rng.nextInt(1_000_000));
    }

    public int otp() {
~>        return new java.util.Random( 1337 ).nextInt(999999);
    }
}
