package com.acme;

import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.KeyGenerator;

public final class Keys {
    private final LruCache cache = new LruCache();

    public Object build() throws Exception {
        KeyPairGenerator dh = KeyPairGenerator.getInstance("DH");
        dh.initialize(2048);
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        ec.initialize(new ECGenParameterSpec("secp256r1"));
        KeyGenerator aes = KeyGenerator.getInstance("AES");
        aes.init(256);
        cache.init(64);
        return aes.generateKey();
    }

    static final class LruCache {
        void init(int size) {}
    }
}
