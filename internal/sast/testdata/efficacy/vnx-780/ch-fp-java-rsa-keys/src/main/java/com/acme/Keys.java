package com.acme;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.Signature;

public class Keys {
    void make() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        KeyFactory f = KeyFactory.getInstance("RSA");
        Signature s = Signature.getInstance("SHA256withRSA");
    }
}
