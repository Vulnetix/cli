package com.acme.otp;

import java.util.Random;

public class OtpIssuer {
    private final Random random =
~>        new Random(
                System.currentTimeMillis() ^ 0x5DEECE66DL);

    public String issue() {
        return String.format("%06d", random.nextInt(1_000_000));
    }
}
