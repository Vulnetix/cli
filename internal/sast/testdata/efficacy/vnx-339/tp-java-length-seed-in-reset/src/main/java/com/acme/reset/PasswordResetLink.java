package com.acme.reset;

import java.security.SecureRandom;
import java.util.Random;

public class PasswordResetLink {
    public String createPasswordReset(String username, String key) {
        Random random = new Random();
~>        random.setSeed(key.length());
        return Integer.toHexString(random.nextInt());
    }

    public byte[] salt(long stamp) throws Exception {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
~>        sr.setSeed(stamp & 0xFFFF);
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return salt;
    }
}
