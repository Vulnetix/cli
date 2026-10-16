package com.acme;

import java.security.MessageDigest;

public class Hasher {
~>    private static MessageDigest sha256;

    static {
        try {
            sha256 = MessageDigest.getInstance("SHA-256");
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    public static byte[] hash(byte[] in) {
        return sha256.digest(in);
    }
}
