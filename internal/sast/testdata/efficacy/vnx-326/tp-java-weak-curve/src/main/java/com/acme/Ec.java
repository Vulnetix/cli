package com.acme;

import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

public class Ec {
    public void gen() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
~>        g.initialize(new ECGenParameterSpec("secp192r1"));
        g.generateKeyPair();
    }
}
