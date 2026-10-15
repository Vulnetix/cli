package com.acme;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class Keys {
    public KeyPair dsa() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("DSA");
~>        g.initialize(1024);
        return g.generateKeyPair();
    }

    public KeyPair dh() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DiffieHellman");
~>        kpg.initialize( 512 );
        return kpg.generateKeyPair();
    }
}
