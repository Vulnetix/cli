package com.acme;

import javax.crypto.Cipher;

public class Crypto {
    private static final Cipher CIPHER;

    static {
        try {
            CIPHER = Cipher.getInstance("AES/GCM/NoPadding");
        } catch (Exception e) {
            log.error("cipher unavailable", e);
            throw new ExceptionInInitializerError(e);
        }
    }
}
