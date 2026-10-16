package com.acme.crypto;

public class Salted {
    private final byte[] salt = new byte[16];

    public byte[] getSalt() {
        return salt;
    }
}
