package com.acme;

import java.security.SecureRandom;

public class Gen {
    private final SecureRandom rnd = new SecureRandom();

    public byte[] salt() {
        byte[] salt = new byte[16];
        rnd.nextBytes(salt);
        return salt;
    }

    public byte[] nonce() {
        byte[] nonce = new byte[12];
        rnd.nextBytes(nonce);
        return nonce;
    }

    public byte[] header() {
        byte[] keyHeader = new byte[4];
        System.arraycopy(src, 0, keyHeader, 0, 4);
        return keyHeader;
    }

    private byte[] src = new byte[64];
}
