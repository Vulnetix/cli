package com.acme.security;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class TokenFactory {
    private final Random rng = new SecureRandom();
    private static final SecureRandom SR = new SecureRandom();

    public String sessionToken() {
        String token = Long.toHexString(rng.nextLong());
        return token;
    }

    public String csrfToken() {
        return new BigInteger(130, SR).toString(32);
    }

    public byte[] salt() {
        byte[] salt = new byte[16];
        SR.nextBytes(salt);
        return salt;
    }
}
