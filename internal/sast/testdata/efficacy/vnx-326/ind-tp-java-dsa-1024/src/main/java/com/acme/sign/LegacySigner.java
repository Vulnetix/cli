package com.acme.sign;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class LegacySigner {
    public KeyPair newKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA");
~>        generator.initialize(1024, new SecureRandom());
        return generator.generateKeyPair();
    }
}
