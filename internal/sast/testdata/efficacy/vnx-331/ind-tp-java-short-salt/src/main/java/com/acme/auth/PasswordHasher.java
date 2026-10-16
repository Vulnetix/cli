package com.acme.auth;

import java.security.SecureRandom;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PasswordHasher {
    private final SecureRandom random = new SecureRandom();

    public byte[] hash(char[] password) throws Exception {
~>        byte[] salt = new byte[8];
        random.nextBytes(salt);
        PBEKeySpec spec = new PBEKeySpec(password, salt, 210000, 256);
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
    }
}
