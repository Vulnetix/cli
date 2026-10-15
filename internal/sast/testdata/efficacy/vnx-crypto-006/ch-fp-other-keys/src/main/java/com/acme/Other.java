package com.acme;

import java.security.KeyPairGenerator;
import javax.crypto.KeyGenerator;

public class Other {
    void gen() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        KeyPairGenerator r = KeyPairGenerator.getInstance("RSA");
        r.initialize(3072);
    }
}
