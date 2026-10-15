package com.acme.crypto;

public final class KeyHolder {
    private final byte[] key;
    private final String alg;

    public KeyHolder(String alg, byte[] key) {
        this.alg = alg;
        this.key = key.clone();
    }

~>    public byte[] getKey() { return key; }

    public String getAlg() { return alg; }
}
