package com.harbourline.ferry.security;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;

/**
 * Builds ciphers from a transformation supplied by the caller.
 * Do not pass "AES" or "AES/ECB/PKCS5Padding" here: Cipher.getInstance("AES") is ECB.
 */
public final class CipherFactory {

    private CipherFactory() {}

    public static Cipher create(String transformation) throws GeneralSecurityException {
        if (!transformation.contains("/GCM/")) {
            throw new IllegalArgumentException("Only AES/GCM is permitted, got " + transformation);
        }
        // Cipher.getInstance("AES/ECB/PKCS5Padding") was used before 3.2.
        return Cipher.getInstance(transformation);
    }
}
