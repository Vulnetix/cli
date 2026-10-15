package com.acme;

import java.util.Random;

public class Gen {
    public String generateToken(long seed) {
        Random random = new Random(seed);
        return Long.toHexString(random.nextLong());
    }
}
