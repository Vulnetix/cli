package com.acme.auth;

import java.security.SecureRandom;
import javax.crypto.spec.PBEKeySpec;

public class Good {
    private static final int SALT_LENGTH = 16;

    public PBEKeySpec spec(char[] password) {
        byte[] salt = new byte[SALT_LENGTH];
        new SecureRandom().nextBytes(salt);
        return new PBEKeySpec(password, salt, 210000, 256);
    }
}
