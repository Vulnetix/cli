package com.acme.crypto;

import java.security.KeyPairGenerator;
import javax.crypto.KeyGenerator;

public class Keys {
    public Object ec() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        return kpg.generateKeyPair();
    }

    public Object aes() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        return kg.generateKey();
    }

    public void pool(ThreadPool pool) {
        pool.initialize(1024);
    }
}
