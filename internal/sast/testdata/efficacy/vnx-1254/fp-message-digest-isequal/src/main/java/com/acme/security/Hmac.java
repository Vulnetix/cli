package com.acme.security;

import java.security.MessageDigest;

public final class Hmac {
    // for (i...) if (mac[i] != other[i]) return false;  -- the unsafe form
    public static boolean verifySignature(byte[] expected, byte[] actual) {
        return MessageDigest.isEqual(expected, actual);
    }
}
