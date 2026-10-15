package com.acme;

import java.security.KeyPairGenerator;

public class KeyFactory2 {
    private static final int KEY_SIZE = 1024;
    private KeyPairGenerator generator;

    KeyFactory2() throws Exception {
        this.generator = KeyPairGenerator.getInstance("RSA", "BC");
~>        this.generator.initialize(KEY_SIZE);
    }
}
