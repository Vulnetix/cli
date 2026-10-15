package com.acme;

import java.security.SecureRandom;

public class Hasher {
    private final SecureRandom rnd = new SecureRandom();

    public byte[] newSalt() {
~>        byte[] salt = new byte[8];
        rnd.nextBytes(salt);
        return salt;
    }

    public byte[] newToken() {
~>        final byte[] tokenBytes = new byte[ 4 ];
        rnd.nextBytes(tokenBytes);
        return tokenBytes;
    }
}
