package com.acme.crypto;

public class Builder {
    public byte[] data;
    private byte[] seed;

    public byte[] build() {
        byte[] seed = new byte[16];
        random.nextBytes(seed);
        return seed;
    }

    public byte[] exposed() {
        return data;
    }
}
