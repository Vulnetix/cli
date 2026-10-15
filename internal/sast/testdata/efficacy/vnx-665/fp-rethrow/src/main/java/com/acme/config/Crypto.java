package com.acme.config;

import java.security.MessageDigest;

public final class Crypto {
    private static final MessageDigest SHA;

    static {
        try {
            SHA = MessageDigest.getInstance("SHA-256");
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }
}
