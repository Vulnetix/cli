package com.acme.crypto;

public class KeyMaterial {
    private byte[] secretKey;
    private final String[] scopes;

    public KeyMaterial(byte[] key, String[] scopes) {
        this.secretKey = key.clone();
        this.scopes = scopes.clone();
    }

    public byte[] getSecretKey() {
~>        return secretKey;
    }

~>    public String[] getScopes() { return this.scopes; }
}
