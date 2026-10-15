package com.acme;

import java.security.SecureRandom;

public class KeyFactory {
    public byte[] newKey() throws Exception {
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");
~>        rng.setSeed(42L);
        byte[] key = new byte[32];
        rng.nextBytes(key);
        return key;
    }

    public byte[] newSalt() throws Exception {
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");
~>        rng.setSeed(System.nanoTime());
        byte[] salt = new byte[16];
        rng.nextBytes(salt);
        return salt;
    }
}
