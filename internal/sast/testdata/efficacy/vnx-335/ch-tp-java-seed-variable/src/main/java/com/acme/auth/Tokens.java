package com.acme.auth;

import java.util.Random;

public class Tokens {
    public String sessionToken() {
        long seed = System.currentTimeMillis();
~>        Random rnd = new Random(seed);
        String sessionToken = Long.toHexString(rnd.nextLong());
        return sessionToken;
    }
}
