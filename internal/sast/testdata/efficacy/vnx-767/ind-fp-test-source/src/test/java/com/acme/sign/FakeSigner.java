package com.acme.sign;

import java.security.PrivateKey;

public class FakeSigner {
    private PrivateKey privateKey;
    private char[] password = "test".toCharArray();

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public char[] getPassword() { return password; }
}
