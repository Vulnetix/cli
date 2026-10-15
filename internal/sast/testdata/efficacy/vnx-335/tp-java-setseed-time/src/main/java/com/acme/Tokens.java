package com.acme;

import java.security.SecureRandom;

public class Tokens {
    public String token() throws Exception {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
~>        sr.setSeed(System.currentTimeMillis());
        byte[] b = new byte[16];
        sr.nextBytes(b);
        return toHex(b);
    }

    public byte[] salt() throws Exception {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
~>        sr.setSeed(12345L);
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return salt;
    }

    private String toHex(byte[] b) { return ""; }
}
