package com.acme.pki;

import java.security.KeyPairGenerator;

public class Keys {
    private static final int TIMEOUT = 1024;

    public Object make() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(3072);
        return kpg.generateKeyPair();
    }
}
