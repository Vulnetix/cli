package com.example.auth;

import java.security.MessageDigest;

public class TokenHasher {
    private static final String HASH_ALGORITHM = "SHA-1";

    byte[] hash(byte[] token) throws Exception {
~>        return MessageDigest.getInstance(HASH_ALGORITHM).digest(token);
    }
}
