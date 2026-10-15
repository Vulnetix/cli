package com.acme.crypto;

public class KeyHolder {
    private byte[] secretKey;
    private final String[] roles;

    public byte[] getSecretKey() {
~>        return secretKey;
    }

~>    public String[] getRoles() { return roles; }
}
