package com.acme;

import java.security.SecureRandom;

public class Salts {
    private final SecureRandom random = new SecureRandom();

    public byte[] salt() {
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    public byte[] gcmNonce() {
        byte[] nonce = new byte[12];
        random.nextBytes(nonce);
        return nonce;
    }

    public byte[] header() {
        byte[] tokenHeader = new byte[4];
        tokenHeader[0] = 0x01;
        return tokenHeader;
    }
}
