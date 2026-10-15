package com.acme.security;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class PasswordHasher {
    private final Random random = new Random();

    public byte[] hash(char[] password) throws NoSuchAlgorithmException {
        byte[] salt = new byte[16];
~>        random.nextBytes(salt);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(salt);
        return md.digest(new String(password).getBytes());
    }
}
