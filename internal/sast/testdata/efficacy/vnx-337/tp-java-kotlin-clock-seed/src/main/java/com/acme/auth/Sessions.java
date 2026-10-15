package com.acme.auth;

import java.security.SecureRandom;
import java.util.Random;

public class Sessions {
    public byte[] salt() throws Exception {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
~>        sr.setSeed(System.currentTimeMillis());
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return salt;
    }

    public String generateSessionId() {
~>        Random rnd = new Random(System.nanoTime());
        return Long.toHexString(rnd.nextLong());
    }
}
