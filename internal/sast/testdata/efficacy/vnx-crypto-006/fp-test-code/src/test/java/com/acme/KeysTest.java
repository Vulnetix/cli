package com.acme;

import java.security.KeyPairGenerator;

public class KeysTest {
    void fastKeys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
    }
}
