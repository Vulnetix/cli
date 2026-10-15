package com.acme.token;

import javax.crypto.Cipher;

public class TokenCrypto {
    // The old default was "AES"; it is kept only as a label for migration logs.
    private static final String LEGACY_LABEL = "AES";
    private static final String TRANSFORM = "AES/GCM/NoPadding";

    public Cipher newCipher() throws Exception {
        System.out.println("migrating from " + LEGACY_LABEL);
        return Cipher.getInstance(TRANSFORM);
    }
}
