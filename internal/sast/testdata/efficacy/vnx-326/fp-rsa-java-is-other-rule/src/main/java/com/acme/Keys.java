package com.acme;

import java.security.KeyPairGenerator;
import javax.crypto.KeyGenerator;

public class Keys {
    public void gen() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("DSA");
        g.initialize(2048);
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        KeyGenerator hm = KeyGenerator.getInstance("HmacSHA256");
        hm.init(256);
        StringBuilder sb = new StringBuilder();
        sb.ensureCapacity(512);
        cache.init(64);
    }
}
