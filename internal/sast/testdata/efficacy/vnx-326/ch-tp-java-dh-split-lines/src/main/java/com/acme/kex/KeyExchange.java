package com.acme.kex;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

public final class KeyExchange {
    public static KeyPair dh() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("DH");
~>        generator.initialize(1024);
        return generator.generateKeyPair();
    }

    public static KeyPair dsa() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("DSA");
~>        gen.initialize(512, new SecureRandom());
        return gen.generateKeyPair();
    }
}
