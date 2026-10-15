package com.acme;

import java.util.Random;

public class Reset {
~>    private final Random random = new Random(System.currentTimeMillis());

    public String resetToken() {
        String token = Long.toHexString(random.nextLong());
        return token;
    }
}
