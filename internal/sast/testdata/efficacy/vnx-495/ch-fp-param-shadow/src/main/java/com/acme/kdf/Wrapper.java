package com.acme.kdf;

public class Wrapper {
    private byte[] key;

    public byte[] identity(byte[] key) {
        return key;
    }

    public byte[] pick(byte[] a,
                       byte[] key) {
        return key;
    }
}
